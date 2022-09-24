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

const TCP_FLAG_INCSEQ = TCP_FLAGS.RST | TCP_FLAGS.FIN | TCP_FLAGS.SYN;

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
    private got_packet_since_ack: boolean = false;

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

    public noDelay: boolean = false;
    private lastSend: number = 0;

    private sackSupported: boolean = false;

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
        }

        if (this.iface) {
            this.saddr = this.iface.getIP();
        }

        if (!this.saddr) {
            this.emit("error", new Error("No route to host"));
            return;
        }

        this.mss = (this.iface?.getMTU() || 1280) - 40;
        do {
            this.sport = makeRandomPort();
            this.setId();
        } while (tcpConns.has(this.connId) || tcpListeners.has(this.sport));
        tcpConns.set(this.connId, this);

        const synPkt = this.makeTcp();
        synPkt.setFlag(TCP_FLAGS.SYN);
        synPkt.setOption(0x04, new Uint8Array()); // SACK
        synPkt.fillMSS(this.mss);
        const ip = this.makeIp(true);
        this.pushPBuffer(ip, synPkt);
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

    private isInEitherWindow(seqno: number) {
        const diff = this.calcWindowDiff(seqno);
        return (diff >= 0) && (diff <= this.rwnd_ackd || diff <= this.rwnd);
    }

    private gotPacket(ipHdr: IPHdr, tcpPkt: TCPPkt) {
        this.got_packet_since_ack = true;

        if (isNaN(this.ackno)) {
            this.handlePacket(ipHdr, tcpPkt);
            this.postHandlePacket();
            return;
        }

        if (!this.isInEitherWindow(tcpPkt.seqno)) {
            this.rejectPkt(ipHdr, tcpPkt, `Out of window (${this.calcWindowDiff(tcpPkt.seqno)} > ${Math.max(this.rwnd, this.rwnd_ackd)}`);
            return;
        }

        if (this.sackSupported) {
            const options = tcpPkt.decodeOptions();
            const sackOption = options.get(0x05);
            if (sackOption) {
                const sackWindows = [];
                for (let i = 0; i < sackOption.byteLength; i += 8) {
                    const begin = sackOption[i+3] | (sackOption[i+2] << 8) | (sackOption[i+1] << 16) | (sackOption[i+0] << 24);
                    const end = sackOption[i+7] | (sackOption[i+6] << 8) | (sackOption[i+5] << 16) | (sackOption[i+4] << 24);
                    sackWindows.push({
                        begin: (begin - this.ackno) | 0,
                        end: (end - this.ackno) | 0,
                    });
                }

                for (let i = 0; i < this.pbufferoffset; i++) {
                    const pkt = this.pbuffer[i];
                    const pktBegin = (pkt.tcp.seqno - this.ackno) | 0;
                    const pktEnd = (pkt.seqend - this.ackno) | 0;

                    for (const sackWindow of sackWindows) {
                        if (sackWindow.begin <= pktBegin && sackWindow.end >= pktEnd) {
                            this.pbuffer.splice(i, 1);
                            this.pbufferoffset -= 1;
                            this.pbufferbytes -= TCPConn.tcpSize(pkt.tcp);
                            console.log('SACK got', i);
                        }
                    }
                }

                console.log('RX SACK', sackWindows);
            }
        }

        this.rbuffer.set(tcpPkt.seqno, {
            ip: ipHdr,
            tcp: tcpPkt,
        });

        let pkt: RPacket | undefined;
        while (pkt = this.rbuffer.get(this.ackno)) {
            this.rbuffer.delete(this.ackno);
            this.handlePacket(pkt.ip, pkt.tcp);
        }

        this.postHandlePacket();
    }

    private postHandlePacket() {
        if (this.rbuffer.size > 0 && this.sackSupported) {
            const sackRegions = [];
            const ipPkt = this.makeIp(true);
            const tcpPkt = this.makeTcp();

            const rbufferKeysSorted = [...this.rbuffer.keys()].sort((a,b) => a-b);
            let sackRegionBegin = NaN; let sackRegionEnd = NaN;
            for (const key of rbufferKeysSorted) {
                const val = this.rbuffer.get(key)!;
                const len = TCPConn.tcpSize(val.tcp);

                if (((key + 1) | 0) === sackRegionEnd) {
                    sackRegionEnd = key + len;
                } else {
                    if (!isNaN(sackRegionBegin)) {
                        sackRegions.push({begin: sackRegionBegin, end: sackRegionEnd});
                    }
                    sackRegionBegin = key;
                    sackRegionEnd = key + len;
                }
            }
            if (!isNaN(sackRegionBegin)) {
                sackRegions.push({begin: sackRegionBegin, end: sackRegionEnd});
            }

            const sackRegionsU8 = new  Uint8Array(sackRegions.length * 8);
            let i = 0;
            for (const region of sackRegions) {
                sackRegionsU8[i] = region.begin & 0xFF;
                sackRegionsU8[i+1] = (region.begin >>> 24) & 0xFF;
                sackRegionsU8[i+2] = (region.begin >>> 16) & 0xFF;
                sackRegionsU8[i+3] = (region.begin >>> 8) & 0xFF;
                sackRegionsU8[i+4] = region.end & 0xFF;
                sackRegionsU8[i+5] = (region.end >>> 24) & 0xFF;
                sackRegionsU8[i+6] = (region.end >>> 16) & 0xFF;
                sackRegionsU8[i+7] = (region.end >>> 8) & 0xFF;
                i += 8;
            }

            tcpPkt.setOption(0x05, sackRegionsU8);
            console.log('TX SACK', sackRegions);
            this.pushPBuffer(ipPkt, tcpPkt);
        }

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

        const len = TCPConn.tcpSize(tcpPkt);
        this.wwnd = tcpPkt.windowSize;
        if (len > 0) {
            this.ackno = (this.ackno + len) & 0xFFFFFFFF;
            if (tcpPkt.data && tcpPkt.data.byteLength > 0 && this.state === TCP_STATE.ESTABLISHED) {
                this.emit("data", tcpPkt.data);
            }
        }

        switch (this.state) {
            case TCP_STATE.LISTENING:
                if (tcpPkt.flags !== TCP_FLAGS.SYN) {
                    this.rejectPkt(ipHdr, tcpPkt, "Expected SYN");
                    return;
                }

                this.ackno = tcpPkt.seqno + len;
                this.state = TCP_STATE.SYN_RECEIVED;

                const replyPkt = this.makeTcp();
                replyPkt.setFlag(TCP_FLAGS.SYN);
                replyPkt.fillMSS(this.mss);
                replyPkt.setOption(0x04, new Uint8Array()); // SACK
                this.pushPBuffer(this.makeIp(true), replyPkt);

                if (tcpPkt.decodeOptions().has(0x04)) {
                    this.sackSupported = true;
                }
                break;

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

                this.ackno = tcpPkt.seqno + len;

                this.state = TCP_STATE.ESTABLISHED;
                if (tcpPkt.decodeOptions().has(0x04)) {
                    this.sackSupported = true;
                }

                this.emit("connect", undefined);
                break;

            case TCP_STATE.ESTABLISHED:
                if (tcpPkt.hasFlag(TCP_FLAGS.FIN)) {
                    this.state = TCP_STATE.CLOSE_WAIT;
                    this.emit("close", undefined);

                    this.state = TCP_STATE.LAST_ACK;
                    const replyPkt = this.makeTcp();
                    replyPkt.setFlag(TCP_FLAGS.FIN);
                    this.pushPBuffer(this.makeIp(true), replyPkt);
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
    }

    private processWPBuffer() {
        this.processPBuffer();

        const needACK = this.got_packet_since_ack || (!isNaN(this.ackno) && this.ackno !== this.ackno_sent);

        const now = Date.now();
        if (this.processWBuffer(needACK || (now - this.lastSend) > 100)) {
            this.processPBuffer();
            return;
        }

        if (needACK) {
            const ip = this.makeIp(true);
            const tcp = this.makeTcp();
            this.pushPBuffer(ip, tcp);
        }

        this.processPBuffer();
    }

    private processWBuffer(noBuffer: boolean) {
        if (this.state !== TCP_STATE.ESTABLISHED) {
            return false;
        }

        const maxSend = Math.min(this.wwnd - this.pbufferbytes, this.mss);
        if (maxSend <= 0) {
            return false;
        }

        const avail = this.wbuffer.length();
        if (avail <= 0) {
            return false;
        }

        if (!this.noDelay && !noBuffer && avail < maxSend) {
            return false;
        }

        const ip = this.makeIp();
        const tcp = this.makeTcp();
        tcp.data = this.wbuffer.read(Math.min(avail, maxSend));
        this.pushPBuffer(ip, tcp);
        return true;
    }

    private processPBuffer() {
        for (; this.pbufferoffset < this.pbuffer.length; this.pbufferoffset++) {
            const pkt = this.pbuffer[this.pbufferoffset];

            sendIPPacket(pkt.ip, pkt.tcp, this.iface);
            this.lastSend = Date.now();
            if (TCPConn.tcpSize(pkt.tcp) === 0) {
                this.pbuffer.pop();
                this.pbufferoffset--;
            }

            this.ackno_sent = pkt.tcp.ackno;
            if (this.ackno_sent === this.ackno) {
                this.got_packet_since_ack = false;
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
        const now = Date.now();

        for (const seqno of this.rbuffer.keys()) {
            if (!this.isInEitherWindow(seqno)) {
                this.rbuffer.delete(seqno);
            }
        }

        this.processWPBuffer();

        if (this.pbufferoffset >= 1) {
            const pkt = this.pbuffer[0];
            if (pkt.nextSend <= now) {
                sendIPPacket(pkt.ip, pkt.tcp, this.iface);
                this.lastSend = Date.now();
                pkt.retries++;
                if (pkt.retries > 3) {
                    this.kill();
                    return;
                }
                pkt.nextSend = this.calcNextSend(pkt.retries);
            }
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
        if (!isNaN(this.ackno)) {
            tcp.ackno = this.ackno;
            tcp.setFlag(TCP_FLAGS.ACK);
        } else {
            tcp.ackno = 0;
        }
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
        }, 100);
    }
}

export function enableTCPEcho() {
    tcpListen(7, TCPEchoListener);
}
