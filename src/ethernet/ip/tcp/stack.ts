import { IInterface } from "../../../interface/index.js";
import { Buffer } from "../../../util/buffer.js";
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
    // Done
    CLOSED = 0,
    LISTENING = 1,

    // Handshaking
    SYN_SENT = 2,
    SYN_RECEIVED = 3,

    // Ready
    ESTABLISHED = 4,

    // Local close
    FIN_WAIT_1 = 5, // FIN sent
    FIN_WAIT_2 = 6, // FIN ACK'd
    CLOSING = 7,
    TIME_WAIT = 8,

    // Remote close
    CLOSE_WAIT = 9,
    LAST_ACK = 10,
}

const TCP_FLAG_INCSEQ = ~(TCP_FLAGS.PSH | TCP_FLAGS.ACK);

interface WPacket {
    ip: IPHdr;
    tcp: TCPPkt;

    seqend: number;

    nextSend: number;
    retries: number;
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
    private daddr?: IPAddr;

    private seqno: number = Math.floor(Math.random() * (1 << 30));
    private ackno: number = NaN;

    private wwnd = 0; // Max the remote end wants us to send
    private rwnd = 65535; // Max we want the remote end to send

    private mss = -1;

    private connId: string = "";
    private iface?: IInterface;

    private state = TCP_STATE.CLOSED;

    private wbuffer = new Buffer(); // Data write buffer

    private pbuffer: WPacket[] = []; // Packet sent buffer
    private pbufferoffset: number = 0; // Offset of last sent element within buffer (for resend)
    private pbufferbytes: number = 0;

    public kill() {
        const ip = this.makeIp(true);
        const tcp = this.makeTcp();
        tcp.flags = TCP_FLAGS.RST;
        sendIPPacket(ip, tcp, this.iface);
        this.delete();
    }

    public close() {
        if (this.state !== TCP_STATE.ESTABLISHED) {
            return;
        }
        this.state = TCP_STATE.FIN_WAIT_1;
        const ip = this.makeIp(true);
        const tcp = this.makeTcp();
        tcp.setFlag(TCP_FLAGS.FIN);
        this.pushPBuffer(ip, tcp);
    }

    public connect(daddr: IPAddr, dport: number, iface?: IInterface) {
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

        const syn = this.makeTcp();
        syn.unsetFlag(TCP_FLAGS.ACK);
        syn.setFlag(TCP_FLAGS.SYN);
        const ip = this.makeIp(true);
        this.pushPBuffer(ip, syn);
        this.state = TCP_STATE.SYN_SENT;
        this.processWPBuffer();
    }

    public send(data: Uint8Array) {
        if (!data || !data.byteLength) {
            return;
        }

        this.wbuffer.add(data);
        this.processWPBuffer();
    }

    public getId() {
        return this.connId;
    }

    public toString() {
        return `IF=${this.iface},DADDR=${this.daddr},SPORT=${this.sport},DPORT=${this.dport},ID=${this.getId()}`;
    }

    private calcNextSend(retries: number) {
        return Date.now() + (2000 * (retries + 1));
    }

    private pushPBuffer(ip: IPHdr, tcp: TCPPkt) {
        const len = TCPConn.tcpSize(tcp);
        this.seqno = (this.seqno + len) & 0xFFFFFFFF;
        this.pbufferbytes += len;
        this.pbuffer.push({
            ip,
            tcp,
            seqend: this.seqno,
            nextSend: this.calcNextSend(0),
            retries: 0,
        });
    }

    private accept(ipHdr: IPHdr, tcpPkt: TCPPkt, iface: IInterface) {
        this.state =  TCP_STATE.LISTENING;
        this.daddr = ipHdr.saddr;
        this.dport = tcpPkt.sport;
        this.sport = tcpPkt.dport;
        this.iface = iface;
        this.mss = iface.getMTU() - 40;
        this.setId();
        tcpConns.set(this.connId, this);
        this.gotPacket(ipHdr, tcpPkt);
    }

    private isAllACK() {
        return this.pbuffer.length === 0;
    }

    private rejectPkt(ip: IPHdr, tcpPkt: TCPPkt, reason: string) {
        console.log(`Rejecting packet: ${reason}`, this, ip, tcpPkt);
    }

    private gotPacket(ipHdr: IPHdr, tcpPkt: TCPPkt) {
        tcpPkt.unsetFlag(TCP_FLAGS.PSH);

        if (!isNaN(this.ackno) && tcpPkt.seqno !== this.ackno) {
            // Buffer it for out-of-order reorder!
            this.rejectPkt(ipHdr, tcpPkt, "Wrong sequence from remote end");
            return;
        }

        if (this.state !== TCP_STATE.LISTENING && this.state !== TCP_STATE.SYN_SENT && tcpPkt.hasFlag(TCP_FLAGS.SYN)) {
            this.rejectPkt(ipHdr, tcpPkt, "Unexpected SYN");
            return;
        }

        if (tcpPkt.hasFlag(TCP_FLAGS.RST)) {
            this.rejectPkt(ipHdr, tcpPkt, "RST received");
            this.delete();
            return;
        }

        if (tcpPkt.hasFlag(TCP_FLAGS.ACK)) {
            for (let i = 0; i < this.pbufferoffset; i++) {
                const pkt = this.pbuffer[i];
                if (pkt.seqend === tcpPkt.ackno) {
                    const toACK = i + 1;
                    this.pbufferoffset -= toACK;
                    const ackdPkts = this.pbuffer.splice(0, toACK);
                    for (const ackdPkt of ackdPkts) {
                        this.pbufferbytes -= TCPConn.tcpSize(ackdPkt.tcp);
                    }
                    break;
                }
            }
        }

        switch (this.state) {
            case TCP_STATE.LISTENING:
                if (tcpPkt.flags !== TCP_FLAGS.SYN) {
                    this.rejectPkt(ipHdr, tcpPkt, "Expected SYN");
                    return;
                }
                this.ackno = tcpPkt.seqno;
                this.state = TCP_STATE.SYN_RECEIVED;

                const ip = this.makeIp(true);
                const tcp = this.makeTcp();
                tcp.setFlag(TCP_FLAGS.SYN);
                this.pushPBuffer(ip, tcp);
                return;

            case TCP_STATE.SYN_RECEIVED:
                if (tcpPkt.flags !== TCP_FLAGS.ACK) {
                    this.rejectPkt(ipHdr, tcpPkt, "Expected ACK");
                    return;
                }

                this.state = TCP_STATE.ESTABLISHED;
                this.emit("connect", undefined);
                break;

            case TCP_STATE.SYN_SENT:
                if (tcpPkt.flags !== (TCP_FLAGS.SYN | TCP_FLAGS.ACK)) {
                    this.rejectPkt(ipHdr, tcpPkt, "Expected SYN+ACK");
                    return;
                }
                this.ackno = tcpPkt.seqno;
                this.state = TCP_STATE.ESTABLISHED;
                this.emit("connect", undefined);
                break;

            case TCP_STATE.ESTABLISHED:
                if (tcpPkt.hasFlag(TCP_FLAGS.FIN)) {
                    this.state = TCP_STATE.CLOSE_WAIT;
                    this.emit("close", undefined);

                    this.state = TCP_STATE.LAST_ACK;
                    const ip = this.makeIp(true);
                    const tcp = this.makeTcp();
                    tcp.setFlag(TCP_FLAGS.FIN);
                    this.pushPBuffer(ip, tcp);
                    return;
                }
                break;

            case TCP_STATE.FIN_WAIT_1:
                if (tcpPkt.hasFlag(TCP_FLAGS.FIN) && this.pbufferoffset === 0) {
                    this.state = TCP_STATE.TIME_WAIT;
                } else if (tcpPkt.hasFlag(TCP_FLAGS.FIN)) {
                    this.state = TCP_STATE.CLOSING;
                } else if (this.isAllACK()) {
                    this.state = TCP_STATE.FIN_WAIT_2;
                }
                break;

            case TCP_STATE.FIN_WAIT_2:
                if (tcpPkt.hasFlag(TCP_FLAGS.FIN)) {
                    this.state = TCP_STATE.TIME_WAIT;
                }
                break;

            case TCP_STATE.LAST_ACK:
            case TCP_STATE.CLOSING:
                if (this.isAllACK()) {
                    this.state = TCP_STATE.TIME_WAIT;
                }
                break;
        }

        let needACK = false;

        const len = TCPConn.tcpSize(tcpPkt);
        if (len > 0) {
            this.ackno = (this.ackno + len) & 0xFFFFFFFF;
            if (tcpPkt.data && tcpPkt.data.byteLength > 0) {
                this.emit("data", tcpPkt.data);
            }
            needACK = true;
        }

        this.wwnd = tcpPkt.windowSize;
        this.processWPBuffer(needACK);

        if (this.state === TCP_STATE.TIME_WAIT) {
            this.delete();
            return;
        }
    }

    private processWPBuffer(needACK: boolean = false) {
        this.processWBuffer();

        if (needACK && this.pbuffer.length <= this.pbufferoffset) {
            const ip = this.makeIp(true);
            const tcp = this.makeTcp();
            this.pushPBuffer(ip, tcp);
        }

        this.processPBuffer();
    }

    private processWBuffer() {
        if (this.state !== TCP_STATE.ESTABLISHED) {
            return;
        }

        const maxSend = Math.min(this.wbuffer.length(), this.wwnd - this.pbufferbytes, this.mss);
        if (maxSend <= 0) {
            return;
        }

        const ip = this.makeIp();
        const tcp = this.makeTcp();
        tcp.data = this.wbuffer.read(maxSend);
        this.pushPBuffer(ip, tcp);
    }

    private processPBuffer() {
        for (; this.pbufferoffset < this.pbuffer.length; this.pbufferoffset++) {
            const pkt = this.pbuffer[this.pbufferoffset];
            sendIPPacket(pkt.ip, pkt.tcp, this.iface);
            if (TCPConn.tcpSize(pkt.tcp) === 0) {
                this.pbuffer.pop();
                this.pbufferoffset--;
            }
        }
    }

    private static tcpSize(tcp: TCPPkt) {
        let len = tcp.data?.byteLength || 0;
        if (tcp.flags & TCP_FLAG_INCSEQ) {
            len++;
        }
        return len;
    }

    public cycle() {
        if (this.pbufferoffset < 1) {
            return;
        }

        const pkt = this.pbuffer[0];
        const now = Date.now();
        if (pkt.nextSend <= now) {
            sendIPPacket(pkt.ip, pkt.tcp, this.iface);
            pkt.retries++;
            if (pkt.retries > 3) {
                this.kill();
                return;
            }
            pkt.nextSend = this.calcNextSend(pkt.retries);
        }
    }

    public delete() {
        this.state = TCP_STATE.CLOSED;

        this.pbuffer = [];
        this.wbuffer.reset();
        this.pbufferoffset = 0;
        this.pbufferbytes = 0;

        this.emit("close", undefined);
        tcpConns.delete(this.connId);
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
        tcp.windowSize = this.rwnd;
        tcp.dport = this.dport;
        tcp.sport = this.sport;
        tcp.seqno = this.seqno;
        tcp.ackno = this.ackno;
        tcp.setFlag(TCP_FLAGS.ACK);
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
