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
    SYN_RECEIVED_1 = 3,
    SYN_RECEIVED_2 = 4,

    // Ready
    ESTABLISHED = 5,

    // Local close
    FIN_WAIT_1 = 6, // FIN sent
    FIN_WAIT_2 = 7, // FIN ACK'd
    CLOSING = 8,
    TIME_WAIT = 9,

    // Remote close
    CLOSE_WAIT = 10,
    LAST_ACK = 11,
}

const TCP_FLAG_INCSEQ = ~(TCP_FLAGS.PSH | TCP_FLAGS.ACK);

interface RPacket {
    ip: IPHdr;
    tcp: TCPPkt;
}

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

        const id = tcpMakeId(ipHdr.daddr!, ipHdr.saddr!, tcpPkt.dport, tcpPkt.sport);
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

        // Refuse packet actively
        const rstIpHdr = new IPHdr();
        rstIpHdr.protocol = IPPROTO.TCP;
        rstIpHdr.saddr = ipHdr.daddr;
        rstIpHdr.daddr = ipHdr.saddr;
        rstIpHdr.df = true;

        const rstTcpPkt = new TCPPkt();
        rstTcpPkt.windowSize = 0;
        rstTcpPkt.dport = tcpPkt.sport;
        rstTcpPkt.sport = tcpPkt.dport;
        rstTcpPkt.seqno = tcpPkt.ackno;
        rstTcpPkt.ackno = (tcpPkt.seqno + TCPConn.tcpSize(tcpPkt)) & 0xFFFFFFFF;
        rstTcpPkt.setFlag(TCP_FLAGS.RST);
        rstTcpPkt.setFlag(TCP_FLAGS.ACK);

        sendIPPacket(rstIpHdr, rstTcpPkt, iface);
    }

    public sport = 0;
    public dport = 0;
    private saddr?: IPAddr;
    private daddr?: IPAddr;

    private seqno: number = Math.floor(Math.random() * (1 << 30));
    private ackno: number = NaN;
    private ackno_sent: number = NaN;

    private wwnd = 0; // Max the remote end wants us to send
    private rwnd = 65535; // Max we want the remote end to send
    private rwnd_ackd = 65535; // Max window ACK'd by the remote end

    private mss = -1;

    private connId: string = "";
    private iface?: IInterface;

    private state = TCP_STATE.CLOSED;

    private wbuffer = new Buffer(); // Data write buffer

    private pbuffer: WPacket[] = []; // Packet sent buffer
    private pbufferoffset: number = 0; // Offset of last sent element within buffer (for resend)
    private pbufferbytes: number = 0;

    private rbuffer: Map<number, RPacket> = new Map();

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
            if (!route) {
                this.emit("error", new Error("No route to host"));
                return;
            }
            this.iface = route.iface;
            this.saddr = route.src;
        } else {
            this.saddr = this.iface.getIP();
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
        this.saddr = ipHdr.daddr;
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

    private calcWindowDiff(seqno: number) {
        return (seqno - this.ackno) | 0;
    }

    private isInWindow(seqno: number) {
        const diff = this.calcWindowDiff(seqno);
        return (diff >= 0) && (diff <= this.rwnd_ackd || diff <= this.rwnd);
    }

    private gotPacket(ipHdr: IPHdr, tcpPkt: TCPPkt) {
        if (isNaN(this.ackno)) {
            this.handlePacket(ipHdr, tcpPkt);
            this.postHandlePacket();
            return;
        }

        if (!this.isInWindow(tcpPkt.seqno)) {
            this.rejectPkt(ipHdr, tcpPkt, `Out of window (${this.calcWindowDiff(tcpPkt.seqno)} > ${Math.max(this.rwnd, this.rwnd_ackd)}`);
            return;
        }

        this.rbuffer.set(tcpPkt.seqno, {
            ip: ipHdr,
            tcp: tcpPkt,
        });

        let pkt: RPacket | undefined;
        while(pkt = this.rbuffer.get(this.ackno)) {
            this.rbuffer.delete(this.ackno);
            this.handlePacket(pkt.ip, pkt.tcp);
        }

        this.postHandlePacket();
    }

    private postHandlePacket() {
        this.processWPBuffer();

        if (this.state === TCP_STATE.TIME_WAIT) {
            this.delete();
            return;
        }
    }

    private handlePacket(ipHdr: IPHdr, tcpPkt: TCPPkt) {
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
                    this.rwnd_ackd = pkt.tcp.windowSize;

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
                this.state = TCP_STATE.SYN_RECEIVED_1;
                break;

            case TCP_STATE.SYN_RECEIVED_1:
                this.rejectPkt(ipHdr, tcpPkt, "Packet in SYN_RECEIVED_1. This should never happen!");
                return;

            case TCP_STATE.SYN_RECEIVED_2:
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

        const len = TCPConn.tcpSize(tcpPkt);
        if (len > 0) {
            this.ackno = (this.ackno + len) & 0xFFFFFFFF;
            if (tcpPkt.data && tcpPkt.data.byteLength > 0 && this.state === TCP_STATE.ESTABLISHED) {
                this.emit("data", tcpPkt.data);
            }
        }

        this.wwnd = tcpPkt.windowSize;
    }

    private processWPBuffer() {
        this.processWBuffer();

        if (this.ackno !== this.ackno_sent && this.pbuffer.length <= this.pbufferoffset) {
            const ip = this.makeIp(true);
            const tcp = this.makeTcp();
            if (this.state === TCP_STATE.SYN_RECEIVED_1) {
                tcp.setFlag(TCP_FLAGS.SYN);
                this.state = TCP_STATE.SYN_RECEIVED_2;
            }
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
            this.ackno_sent = pkt.tcp.ackno;
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
        for (const seqno of this.rbuffer.keys()) {
            if (!this.isInWindow(seqno)) {
                this.rbuffer.delete(seqno);
            }
        }

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
        this.rbuffer.clear();

        this.emit("close", undefined);
        tcpConns.delete(this.connId);
    }

    private makeIp(df = false) {
        const ip = new IPHdr();
        ip.protocol = IPPROTO.TCP;
        ip.saddr = this.saddr;
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
        this.connId = tcpMakeId(this.saddr!, this.daddr!, this.sport, this.dport);
    }
}

function tcpMakeId(saddr: IPAddr, daddr: IPAddr, sport: number, dport: number) {
    return `${saddr}|${daddr}|${sport}|${dport}`;
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
