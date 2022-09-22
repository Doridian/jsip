import { IInterface } from "../../../interface/index.js";
import { EventEmitter } from "../../../util/emitter.js";
import { assertValidPort, makeRandomPort } from "../../../util/port.js";
import { IPAddr } from "../address.js";
import { IPHdr, IPPROTO } from "../index.js";
import { getRoute } from "../router.js";
import { sendIPPacket } from "../send.js";
import { registerIpHandler } from "../stack.js";
import { TCP_FLAGS, TCPPkt } from "./index.js";

export interface ITCPListener {
    gotConnection(tcpConn: TCPConn): void;
}

const tcpConns = new Map<string, TCPConn>();
const tcpListeners = new Map<number, ITCPListener>();

// Public API:
// *connect / *listen / send / close / kill

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

interface IWBufferEntry {
    close?: boolean;
    data?: Uint8Array;
    psh?: boolean;
}

export class TCPConn extends EventEmitter {
    public static gotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr, iface: IInterface) {
        const tcpPkt = TCPPkt.fromPacket(data, offset, len, ipHdr);

        const id = tcpMakeId(ipHdr.saddr!, tcpPkt.dport, tcpPkt.sport);
        const gotConn = tcpConns.get(id);
        if (gotConn) {
            return gotConn.gotPacket(ipHdr, tcpPkt);
        }

        if (tcpPkt.hasFlag(TCP_FLAGS.SYN) && !tcpPkt.hasFlag(TCP_FLAGS.ACK)) {
            const listener = tcpListeners.get(tcpPkt.dport);
            if (listener) {
                const conn = new TCPConn();
                conn.accept(ipHdr, tcpPkt, iface);
                listener.gotConnection(conn);
                return;
            }
        }
    }

    public sport = 0;
    public dport = 0;

    private state = TCP_STATE.CLOSED;
    private daddr?: IPAddr;
    private wseqno?: number;
    private rseqno?: number;
    private wnd = 65535;
    private wbuffers: IWBufferEntry[] = [];
    private rbuffers: Uint8Array[] = [];
    private rbufferlen = 0;
    private wlastack = false;
    private wlastackno = 0;
    private wlastsend = 0;
    private wretrycount = 0;
    private rlastseqno?: number;
    private mss = -1;
    private connId: string = "";
    private iface?: IInterface;

    private lastIp?: IPHdr;
    private lastTcp?: TCPPkt;
    private lastAckIp?: IPHdr;
    private lastAckTcp?: TCPPkt;

    public kill() {
        const ip = this.makeIp(true);
        const tcp = this.makeTcp();
        tcp.flags = 0;
        tcp.setFlag(TCP_FLAGS.RST);
        sendIPPacket(ip, tcp, this.iface);
        this.delete();
    }

    public close() {
        if (!this.wlastack || this.state !== TCP_STATE.ESTABLISHED) {
            this.wbuffers.push({ close: true });
            return;
        }

        const ip = this.makeIp(true);
        const tcp = this.makeTcp();
        tcp.setFlag(TCP_FLAGS.FIN);
        this.sendPacket(ip, tcp);
    }

    public connect(dport: number, daddr: IPAddr, iface?: IInterface) {
        this.state = TCP_STATE.SYN_SENT;
        this.daddr = daddr;
        this.dport = dport;
        this.iface = iface;
        if (!this.iface) {
            const route = getRoute(daddr, iface);
            if (route && route.iface) {
                this.iface = route.iface;
            }
        }

        this.mss = (this.iface?.getMTU() || 1280) - 40;
        do {
            this.sport = makeRandomPort();
            this.setId();
        } while (tcpConns.has(this.connId) || tcpListeners.has(this.sport));
        tcpConns.set(this.connId, this);

        const ip = this.makeIp(true);
        const tcp = this.makeTcp();
        this.sendPacket(ip, tcp);
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

    public send(data: Uint8Array) {
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
            last.psh = true;
            if (!isReady) {
                return;
            }
            data = first;
            psh = false;
        }

        if (!isReady) {
            this.wbuffers.push({ data, psh: true });
            return;
        }

        this.sendInternal(data, psh);
    }

    public getId() {
        return this.connId;
    }

    public toString() {
        return `IF=${this.iface},DADDR=${this.daddr},SPORT=${this.sport},DPORT=${this.dport},ID=${this.getId()}`;
    }

    private accept(ipHdr: IPHdr, tcpPkt: TCPPkt, iface: IInterface) {
        this.state =  TCP_STATE.SYN_RECEIVED;
        this.daddr = ipHdr.saddr;
        this.dport = tcpPkt.sport;
        this.sport = tcpPkt.dport;
        this.iface = iface;
        this.mss = iface.getMTU() - 40;
        this.setId();
        tcpConns.set(this.connId, this);
        this.gotPacket(ipHdr, tcpPkt);
    }

    private gotPacket(_: IPHdr, tcpPkt: TCPPkt) {
        if (this.state === TCP_STATE.CLOSED) {
            return this.kill();
        }

        if (this.rlastseqno !== undefined && tcpPkt.seqno <= this.rlastseqno) {
            if (this.lastAckTcp && this.lastAckIp) {
                sendIPPacket(this.lastAckIp, this.lastAckTcp, this.iface);
            }
            return;
        }

        let wseqno = this.wseqno;
        let rseqno = this.rseqno;

        if (tcpPkt.hasFlag(TCP_FLAGS.SYN)) {
            if (this.state === TCP_STATE.SYN_SENT || this.state === TCP_STATE.SYN_RECEIVED) {
                this.rseqno = tcpPkt.seqno;

                this.incRSeq(1);
                const ip = this.makeIp(true);
                const tcp = this.makeTcp();
                if (this.state === TCP_STATE.SYN_RECEIVED) {
                    this.sendPacket(ip, tcp);
                } else {
                    sendIPPacket(ip, tcp, this.iface);
                }

                rseqno = this.rseqno;
                wseqno = this.wseqno;

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
                throw new Error(`Invalid sequence number (packet.seqno=${tcpPkt.seqno} rseqno=${this.rseqno})`);
            }

            if (tcpPkt.hasFlag(TCP_FLAGS.RST)) {
                this.delete();
                return;
            }

            if (tcpPkt.data && tcpPkt.data.byteLength > 0) {
                this.rlastseqno = rseqno;
                this.incRSeq(tcpPkt.data.byteLength);
                const ip = this.makeIp(true);
                const tcp = this.makeTcp();
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
            if (tcpPkt.ackno === wseqno) {
                this.wlastack = true;
                this.wlastackno = tcpPkt.ackno;
                this.wretrycount = 0;
                if (this.state === TCP_STATE.CLOSING || this.state === TCP_STATE.LAST_ACK) {
                    this.delete();
                } else {
                    const next = this.wbuffers.shift();
                    if (next) {
                        this.sendInternal(next.data, next.psh);
                    } else {
                        this.emit("drain", undefined);
                    }
                }
            } else if (tcpPkt.ackno !== this.wlastackno) {
                throw new Error(`Wrong ACK (packet.ackno=${tcpPkt.ackno} wseqno=${wseqno} wlastackno=${this.wlastackno})`);
            }
        }

        if (tcpPkt.hasFlag(TCP_FLAGS.FIN)) {
            const ip = this.makeIp(true);
            const tcp = this.makeTcp();
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

    private delete() {
        this.state = TCP_STATE.CLOSED;
        this.wbuffers = [];
        this.rbuffers = [];
        this.emit("close", undefined);
        tcpConns.delete(this.connId);
    }

    private sendPacket(ipHdr: IPHdr, tcpPkt: TCPPkt) {
        this.lastIp = ipHdr;
        this.lastTcp = tcpPkt;
        sendIPPacket(ipHdr, tcpPkt, this.iface);
        this.wlastack = false;
        this.wlastsend = Date.now();
    }

    private incRSeq(inc: number) {
        this.rseqno = (this.rseqno! + inc) & 0xFFFFFFFF;
    }

    private incWSeq(inc: number) {
        this.wseqno = (this.wseqno! + inc) & 0xFFFFFFFF;
    }

    private sendInternal(data?: Uint8Array, psh: boolean = false) {
        const ip = this.makeIp();
        const tcp = this.makeTcp();
        tcp.data = data;
        if (psh) {
            tcp.setFlag(TCP_FLAGS.PSH);
        }
        this.sendPacket(ip, tcp);
        this.incWSeq(data ? data.byteLength : 0);
    }

    private makeIp(df = false) {
        const ip = new IPHdr();
        ip.protocol = IPPROTO.TCP;
        ip.saddr = undefined;
        ip.daddr = this.daddr;
        ip.df = df;
        return ip;
    }

    private makeTcp() {
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

    private setId() {
        this.connId = tcpMakeId(this.daddr!, this.sport, this.dport);
    }
}

function tcpMakeId(daddr: IPAddr, sport: number, dport: number) {
    return `${daddr}|${sport}|${dport}`;
}

export function tcpListen(port: number, func: ITCPListener) {
    assertValidPort(port);

    if (tcpListeners.has(port)) {
        return false;
    }

    enableTCP();

    tcpListeners.set(port, func);
    return true;
}

export function tcpCloseListener(port: number) {
    assertValidPort(port);

    return tcpListeners.delete(port);
}

export function tcpConnect(
    ip: IPAddr, port: number,
    iface?: IInterface) {

    assertValidPort(port);

    enableTCP();

    const conn = new TCPConn();
    conn.connect(port, ip, iface);
    return conn;
}

// tslint:disable-next-line:max-classes-per-file
class TCPEchoListener {
    public static gotConnection(tcpConn: TCPConn) {
        if (tcpConn.dport === 7) {
            tcpConn.close();
            return;
        }

        tcpConn.on("data", (dataRaw) => {
            const data = dataRaw as Uint8Array;
            if (data.byteLength > 0 && data.byteLength <= 2 && (data[0] === 10 || data[0] === 13)) {
                tcpConn.close();
            } else {
                tcpConn.send(data);
            }
        });
    }
}


export function enableTCP() {
    if (registerIpHandler(IPPROTO.TCP, TCPConn)) {
        setInterval(() => {
            tcpConns.forEach((conn) => conn.cycle());
        }, 1000);
    }
}

export function enableTCPEcho() {
    tcpListen(7, TCPEchoListener);
}
