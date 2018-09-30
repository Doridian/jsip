import { IInterface } from "../../../interface/index.js";
import { INTERFACE_NONE } from "../../../interface/none.js";
import { EventEmitter } from "../../../util/emitter.js";
import { logError } from "../../../util/log.js";
import { IP_NONE, IPAddr } from "../address.js";
import { IPHdr, IPPROTO } from "../index.js";
import { sendIPPacket } from "../send.js";
import { registerIpHandler } from "../stack.js";
import { TCP_FLAGS, TCPPkt } from "./index.js";

export type TCPListener = (tcpConn: TCPConn) => void;

const tcpConns = new Map<string, TCPConn>();
const tcpListeners = new Map<number, TCPListener>();
tcpListeners.set(
    7,
    (tcpConn) => { // ECHO
        tcpConn.on("data", (data: Uint8Array) => {
            if (data.byteLength > 0 && data.byteLength <= 2 && (data[0] === 10 || data[0] === 13)) {
                tcpConn.close();
            } else {
                tcpConn.send(data);
            }
        });
    },
);

// Public API:
// *connect / *listen / send / close / kill

export const enum TCP_CBTYPE {
    SENT = 0,
    ACKD = 1,
}

const enum TCP_STATE {
    CLOSED = 0,
    SYN_SENT = 1,
    SYN_RECEIVED = 2,
    FIN_WAIT_1 = 3,
    FIN_WAIT_2 = 4,
    CLOSING = 5,
    TIME_WAIT = 6,
    CLOSE_WAIT = 7,
    LAST_ACK = 8,
    ESTABLISHED = 9,
}

const TCP_ONLY_SEND_ON_PSH = false;

const TCP_FLAG_INCSEQ = ~(TCP_FLAGS.PSH | TCP_FLAGS.ACK);

type TCPOnAckHandler = (type: TCP_CBTYPE) => void;

interface IWBufferEntry {
    close?: boolean;
    data?: Uint8Array;
    psh?: boolean;
    cb?: TCPOnAckHandler;
}

export class TCPConn extends EventEmitter {
    private state = TCP_STATE.CLOSED;
    private daddr: IPAddr = IP_NONE;
    private sport = 0;
    private dport = 0;
    private wseqno?: number;
    private rseqno?: number;
    private wnd = 65535;
    private wbuffers: IWBufferEntry[] = [];
    private rbuffers: Uint8Array[] = [];
    private rbufferlen = 0;
    private wlastack = false;
    private wlastsend = 0;
    private wretrycount = 0;
    private rlastseqno?: number;
    private onack = new Map<number, TCPOnAckHandler[]>();
    private mss = -1;
    private connId: string = "";
    private iface: IInterface = INTERFACE_NONE;

    private lastIp?: IPHdr;
    private lastTcp?: TCPPkt;
    private lastAckIp?: IPHdr;
    private lastAckTcp?: TCPPkt;

    constructor() {
        super();
    }

    public _makeIp(df = false) {
        const ip = new IPHdr();
        ip.protocol = IPPROTO.TCP;
        ip.saddr = IP_NONE;
        ip.daddr = this.daddr;
        ip.df = df;
        return ip;
    }

    public _makeTcp() {
        const tcp = new TCPPkt();
        tcp.windowSize = this.wnd;
        tcp.dport = this.dport;
        tcp.sport = this.sport;
        let incSeq = false;
        if (this.wseqno === undefined) {
            this.wseqno = Math.floor(Math.random() * (1 << 30));
            tcp.setFlag(TCP_FLAGS.SYN);
            incSeq = true;
            tcp.fillMSS(this.mss);
        }
        tcp.seqno = this.wseqno;
        if (incSeq) {
            this.incWSeq(1);
        }
        if (this.rseqno !== undefined) {
            tcp.ackno = this.rseqno;
            tcp.setFlag(TCP_FLAGS.ACK);
        }
        return tcp;
    }

    public delete() {
        this.state = TCP_STATE.CLOSED;
        this.wbuffers = [];
        this.rbuffers = [];
        this.emit("close", undefined);
        tcpConns.delete(this.connId);
    }

    public kill() {
        const ip = this._makeIp(true);
        const tcp = this._makeTcp();
        tcp.flags = 0;
        tcp.setFlag(TCP_FLAGS.RST);
        sendIPPacket(ip, tcp, this.iface);
        this.delete();
    }

    public addOnAck(cb?: TCPOnAckHandler) {
        if (!cb) {
            return;
        }

        try {
            cb(TCP_CBTYPE.SENT);
        } catch (e) {
            logError(e.stack || e);
        }

        const ack = this.wseqno!;
        const onack = this.onack.get(ack);
        if (!onack) {
            this.onack.set(ack, [cb]);
            return;
        }
        onack.push(cb);
    }

    public close(cb?: TCPOnAckHandler) {
        if (!this.wlastack || this.state !== TCP_STATE.ESTABLISHED) {
            this.wbuffers.push({ close: true, cb });
            return;
        }

        const ip = this._makeIp(true);
        const tcp = this._makeTcp();
        tcp.setFlag(TCP_FLAGS.FIN);
        this.sendPacket(ip, tcp);
        this.incWSeq(1);

        this.addOnAck(cb);
    }

    public sendPacket(ipHdr: IPHdr, tcpPkt: TCPPkt) {
        this.lastIp = ipHdr;
        this.lastTcp = tcpPkt;
        sendIPPacket(ipHdr, tcpPkt, this.iface);
        this.wlastack = false;
        this.wlastsend = Date.now();
    }

    public incRSeq(inc: number) {
        this.rseqno = (this.rseqno! + inc) & 0xFFFFFFFF;
    }

    public incWSeq(inc: number) {
        this.wseqno = (this.wseqno! + inc) & 0xFFFFFFFF;
    }

    public cycle() {
        if (!this.wlastack && this.lastTcp && this.wlastsend < Date.now() - 1000) {
            if (this.wretrycount > 3) {
                this.kill();
                return;
            }
            if (this.lastIp) {
                sendIPPacket(this.lastIp, this.lastTcp, this.iface);
            }
            this.wretrycount++;
        }
    }

    public send(data: Uint8Array, cb?: TCPOnAckHandler) {
        if (!data || !data.byteLength) {
            return;
        }

        const isReady = this.wlastack && this.state === TCP_STATE.ESTABLISHED;

        let psh = true;
        if (data.byteLength > this.mss) {
            const first = data.slice(0, this.mss);
            if (!isReady) {
                this.wbuffers.push({ data: first, psh: false });
            }
            for (let i = this.mss; i < data.byteLength; i += this.mss) {
                this.wbuffers.push({ data: data.slice(i, i + this.mss), psh: false });
            }
            const last = this.wbuffers[this.wbuffers.length - 1];
            if (cb) {
                last.cb = cb;
            }
            last.psh = true;
            if (!isReady) {
                return;
            }
            data = first;
            cb = undefined;
            psh = false;
        }

        if (!isReady) {
            this.wbuffers.push({ data, cb, psh: true });
            return;
        }

        this._send(data, psh, cb);
    }

    public _send(data?: Uint8Array, psh?: boolean, cb?: TCPOnAckHandler) {
        const ip = this._makeIp();
        const tcp = this._makeTcp();
        tcp.data = data;
        if (psh) {
            tcp.setFlag(TCP_FLAGS.PSH);
        }
        this.sendPacket(ip, tcp);
        this.incWSeq(data ? data.byteLength : 0);
        this.addOnAck(cb);
    }

    public gotPacket(_: IPHdr, tcpPkt: TCPPkt) {
        if (this.state === TCP_STATE.CLOSED) {
            return this.kill();
        }

        if (this.rlastseqno !== undefined && tcpPkt.seqno <= this.rlastseqno) {
            if (this.lastAckTcp && this.lastAckIp) {
                sendIPPacket(this.lastAckIp, this.lastAckTcp, this.iface);
            }
            return;
        }

        let lseqno = this.wseqno;
        let rseqno = this.rseqno;

        if (tcpPkt.hasFlag(TCP_FLAGS.SYN)) {
            if (this.state === TCP_STATE.SYN_SENT || this.state === TCP_STATE.SYN_RECEIVED) {
                this.rseqno = tcpPkt.seqno;

                this.incRSeq(1);
                const ip = this._makeIp(true);
                const tcp = this._makeTcp();
                if (this.state === TCP_STATE.SYN_RECEIVED) {
                    this.sendPacket(ip, tcp);
                } else {
                    sendIPPacket(ip, tcp, this.iface);
                }

                rseqno = this.rseqno;
                lseqno = this.wseqno;

                this.state = TCP_STATE.ESTABLISHED;
                this.emit("connect", undefined);
            } else {
                throw new Error("Unexpected SYN");
            }
        } else {
            if (this.rseqno === undefined) {
                throw new Error("Wanted SYN, but got none");
            }

            if (tcpPkt.seqno !== this.rseqno) {
                throw new Error("Invalid sequence number");
            }

            if (tcpPkt.hasFlag(TCP_FLAGS.RST)) {
                this.delete();
                return;
            }

            if (tcpPkt.data && tcpPkt.data.byteLength > 0) {
                this.rlastseqno = rseqno;
                this.incRSeq(tcpPkt.data.byteLength);
                const ip = this._makeIp(true);
                const tcp = this._makeTcp();
                sendIPPacket(ip, tcp, this.iface);
                this.lastAckIp = ip;
                this.lastAckTcp = tcp;

                if (TCP_ONLY_SEND_ON_PSH) {
                    this.rbufferlen += tcpPkt.data.byteLength;
                    this.rbuffers.push(tcpPkt.data);
                    if (tcpPkt.hasFlag(TCP_FLAGS.PSH)) {
                        const all = new ArrayBuffer(this.rbufferlen);
                        const a8 = new Uint8Array(all);
                        let pos = 0;
                        for (const rbuffer of this.rbuffers) {
                            const b8 = new Uint8Array(rbuffer);
                            for (let j = 0; j < b8.length; j++) {
                                a8[pos + j] = b8[j];
                            }
                            pos += b8.length;
                        }
                        this.rbuffers = [];
                        this.emit("data", new Uint8Array(all));
                    }
                } else {
                    this.emit("data", tcpPkt.data);
                }
            }

            if ((tcpPkt.flags & TCP_FLAG_INCSEQ) !== 0) { // not (only) ACK set?
                this.incRSeq(1);
            }

            if (tcpPkt.mss !== -1) {
                this.mss = tcpPkt.mss;
            }
        }

        if (tcpPkt.hasFlag(TCP_FLAGS.ACK)) {
            if (tcpPkt.ackno === lseqno) {
                const onack = this.onack.get(tcpPkt.ackno);
                if (onack) {
                    onack.forEach((cb) => { try { cb(TCP_CBTYPE.ACKD); } catch (e) { logError(e.stack || e); } });
                    this.onack.delete(tcpPkt.ackno);
                }

                this.wlastack = true;
                this.wretrycount = 0;
                if (this.state === TCP_STATE.CLOSING || this.state === TCP_STATE.LAST_ACK) {
                    this.delete();
                } else {
                    const next = this.wbuffers.shift();
                    if (next) {
                        this._send(next.data, next.psh ? next.psh : false, next.cb);
                    }
                }
            } else {
                throw new Error("Wrong ACK");
            }
        }

        if (tcpPkt.hasFlag(TCP_FLAGS.FIN)) {
            const ip = this._makeIp(true);
            const tcp = this._makeTcp();
            switch (this.state) {
                case TCP_STATE.FIN_WAIT_1:
                case TCP_STATE.FIN_WAIT_2:
                    sendIPPacket(ip, tcp, this.iface); // ACK it
                    if (!tcpPkt.hasFlag(TCP_FLAGS.ACK)) {
                        this.state = TCP_STATE.CLOSING;
                    } else {
                        this.delete();
                    }
                    break;
                case TCP_STATE.CLOSING:
                case TCP_STATE.LAST_ACK:
                    this.delete();
                    sendIPPacket(ip, tcp, this.iface);
                    this.incWSeq(1);
                    break;
                default:
                    this.state = TCP_STATE.LAST_ACK;
                    tcp.setFlag(TCP_FLAGS.FIN);
                    sendIPPacket(ip, tcp, this.iface);
                    this.incWSeq(1);
                    break;
            }
        }
    }

    public accept(ipHdr: IPHdr, tcpPkt: TCPPkt, iface: IInterface) {
        this.state =  TCP_STATE.SYN_RECEIVED;
        this.daddr = ipHdr.saddr;
        this.dport = tcpPkt.sport;
        this.sport = tcpPkt.dport;
        this.iface = iface;
        this.mss = iface.getMTU() - 40;
        this.connId = this.toString();
        tcpConns.set(this.connId, this);
        this.gotPacket(ipHdr, tcpPkt);
    }

    public connect(dport: number, daddr: IPAddr, iface: IInterface) {
        this.state = TCP_STATE.SYN_SENT;
        this.daddr = daddr;
        this.dport = dport;
        this.iface = iface;
        this.mss = iface.getMTU() - 40;
        do {
            this.sport = 4097 + Math.floor(Math.random() * 61347);
            this.connId = this.toString();
        } while (tcpConns.has(this.connId) || tcpListeners.has(this.sport));
        tcpConns.set(this.connId, this);

        const ip = this._makeIp(true);
        const tcp = this._makeTcp();
        this.sendPacket(ip, tcp);
    }

    public toString() {
        return `${this.daddr}|${this.sport}|${this.dport}`;
    }
}

function tcpGotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr, iface: IInterface) {
    const tcpPkt = TCPPkt.fromPacket(data, offset, len, ipHdr);

    const id = `${ipHdr.saddr}|${tcpPkt.dport}|${tcpPkt.sport}`;
    const gotConn = tcpConns.get(id);
    if (gotConn) {
        return gotConn.gotPacket(ipHdr, tcpPkt);
    }

    if (tcpPkt.hasFlag(TCP_FLAGS.SYN) && !tcpPkt.hasFlag(TCP_FLAGS.ACK)) {
        const listener = tcpListeners.get(tcpPkt.dport);
        if (listener) {
            const conn = new TCPConn();
            conn.accept(ipHdr, tcpPkt, iface);
            listener(conn);
            return;
        }
    }
}

export function tcpListen(port: number, func: TCPListener) {
    if (port < 1 || port > 65535) {
        return false;
    }

    if  (tcpListeners.has(port)) {
        return false;
    }

    tcpListeners.set(port, func);
    return true;
}

export function tcpCloseListener(port: number) {
    if (port < 1 || port > 65535) {
        return false;
    }

    if (port === 7) {
        return false;
    }

    tcpListeners.delete(port);
    return true;
}

export function tcpConnect(
    ip: IPAddr, port: number,
    iface?: IInterface) {
    if (port < 1 || port > 65535) {
        throw new Error("Port out of range");
    }

    const conn = new TCPConn();
    conn.connect(port, ip, iface || INTERFACE_NONE);
    return conn;
}

setInterval(() => {
    tcpConns.forEach((conn) => conn.cycle());
}, 1000);

registerIpHandler(IPPROTO.TCP, tcpGotPacket);
