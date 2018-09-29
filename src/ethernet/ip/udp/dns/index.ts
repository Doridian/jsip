import { IInterface } from "../../../../interface/index";
import { INTERFACE_NONE } from "../../../../interface/none";
import { BitArray } from "../../../../util/bitfield";
import { boolToBit } from "../../../../util/index";
import { logError } from "../../../../util/log";
import { bufferToString } from "../../../../util/string";
import { IP_NONE, IPAddr } from "../../address";
import { IPHdr, IPPROTO } from "../../index";
import { sendIPPacket } from "../../send";
import { UDPPkt } from "../index";
import { udpListen } from "../stack";
import { DNSAnswer } from "./answer";
import { DNSQuestion } from "./question";

type DNSResult = IPAddr | string | undefined;
interface IDNSParseState { pos: number; data: Uint8Array; packet: ArrayBuffer; offset: number; }
type DNSCallback = (result: DNSResult) => void;

const dnsCache = new Map<string, DNSResult>();
const dnsQueue = new Map<string, DNSCallback[]>();
const dnsQueueTimeout = new Map<string, number>();

const DNS_SEG_PTR = 0b11000000;
const DNS_SEG_MAX = 0b00111111;

let dnsServerIps: IPAddr[] = [];
const dnsServerIpsByIface = new Map<IInterface, IPAddr[]>();

export const enum DNS_TYPE {
    A = 0x0001,
    CNAME = 0x0005,
    MX = 0x000F,
    NS = 0x0002,
}

export const enum DNS_CLASS {
    IN = 0x0001,
}

function parseDNSLabel(s: IDNSParseState) {
    const res = [];
    const donePointers = new Set<number>();
    let lastPos;
    let dataGood = false;

    while (s.pos < s.data.byteLength) {
        const segLen = s.data[s.pos++];
        if (segLen > DNS_SEG_MAX) {
            if ((segLen & DNS_SEG_PTR) !== DNS_SEG_PTR) {
                throw new Error(`Invalid DNS segment length ${segLen}`);
            }
            if (lastPos === undefined) {
                lastPos = s.pos + 1;
            }
            s.pos = ((segLen & DNS_SEG_MAX) << 8) | s.data[s.pos];
            if (donePointers.has(s.pos)) {
                throw new Error("Recursive pointers detected");
            }
            donePointers.add(s.pos);
            continue;
        }

        if (segLen === 0) {
            dataGood = true;
            break;
        }

        res.push(bufferToString(s.packet, s.pos + s.offset, segLen));
        s.pos += segLen;
    }

    if (lastPos !== undefined) {
        s.pos = lastPos;
    }

    if (!dataGood) {
        throw new Error("Unexpected DNS label end");
    }

    return res.join(".");
}

function parseAnswerSection(count: number, state: IDNSParseState) {
    const data = state.data;
    const answers = [];

    for (let i = 0; i < count; i++) {
        const a = new DNSAnswer();

        a.name = parseDNSLabel(state);
        a.type = data[state.pos + 1] + (data[state.pos] << 8);
        a.class = data[state.pos + 3] + (data[state.pos + 2] << 8);
        a.ttl = data[state.pos + 7] +
            (data[state.pos + 6] << 8) +
            (data[state.pos + 5] << 16) +
            (data[state.pos + 4] << 24);
        const rdlength = data[state.pos + 9] + (data[state.pos + 8] << 8);
        state.pos += 10;

        a.datapos = state.pos;
        a.data = new Uint8Array(state.packet, state.offset + state.pos, rdlength);
        state.pos += rdlength;

        answers.push(a);
    }

    return answers;
}

export class DNSPkt {
    public static fromPacket(packet: ArrayBuffer, offset: number) {
        const data = new Uint8Array(packet, offset);
        const bit = new BitArray(packet, offset + 2);

        const dns = new DNSPkt();
        dns.id = data[1] + (data[0] << 8);

        // [2]
        dns.qr = bit.bool();
        dns.opcode = bit.read(4);
        dns.aa = bit.bool();
        dns.tc = bit.bool();
        dns.rd = bit.bool();

        // [3]
        dns.ra = bit.bool();
        bit.skip(3);
        dns.rcode = bit.read(4);

        const qdcount = data[5] + (data[4] << 8);
        const ancount = data[7] + (data[6] << 8);
        const nscount = data[9] + (data[8] << 8);
        const arcount = data[11] + (data[10] << 8);

        dns.questions = [];
        const state = { pos: 12, data, packet, offset };
        for (let i = 0; i < qdcount; i++) {
            const q = new DNSQuestion();
            q.name = parseDNSLabel(state);
            q.type = data[state.pos + 1] + (data[state.pos] << 8);
            q.class = data[state.pos + 3] + (data[state.pos + 2] << 8);
            state.pos += 4;
            dns.questions.push(q);
        }

        dns.answers = parseAnswerSection(ancount, state);
        dns.authority = parseAnswerSection(nscount, state);
        dns.additional = parseAnswerSection(arcount, state);

        return dns;
    }

    public id = 0;
    public qr = false;
    public opcode = 0;
    public aa = false;
    public tc = false;
    public rd = true;
    public ra = false;
    public rcode = 0;
    public questions: DNSQuestion[] = []; // QDCOUNT
    public answers: DNSAnswer[] = []; // ANCOUNT
    public authority: DNSAnswer[] = []; // NSCOUNT
    public additional: DNSAnswer[] = []; // ARCOUNT

    public getFullLength() {
        let len = 12;
        this.questions.forEach((q) => {
            len += (q.name.length + 2) + 4;
        });
        this.answers.forEach((a) => {
            len += (a.name.length + 2) + 10 + (a.data ? a.data.byteLength : 0);
        });
        this.authority.forEach((a) => {
            len += (a.name.length + 2) + 10 + (a.data ? a.data.byteLength : 0);
        });
        this.additional.forEach((a) => {
            len += (a.name.length + 2) + 10 + (a.data ? a.data.byteLength : 0);
        });
        return len;
    }

    public toPacket(array: ArrayBuffer, offset: number) {
        return this._toPacket(new Uint8Array(array, offset));
    }

    public toBytes() {
        const packet = new Uint8Array(this.getFullLength());
        this._toPacket(packet);
        return packet;
    }

    public _toPacket(packet: Uint8Array) {
        packet[0] = (this.id >>> 8) & 0xFF;
        packet[1] = this.id & 0xFF;
        packet[2] = boolToBit(this.qr, 7) |
                    (this.opcode << 3) |
                    boolToBit(this.aa, 2) |
                    boolToBit(this.tc, 1) |
                    boolToBit(this.rd, 0);
        packet[3] = boolToBit(this.ra, 7) | this.rcode;

        const qdcount = this.questions.length;
        const ancount = this.answers.length;
        const nscount = this.authority.length;
        const arcount = this.additional.length;

        packet[4] = (qdcount >>> 8) & 0xFF;
        packet[5] = qdcount & 0xFF;
        packet[6] = (ancount >>> 8) & 0xFF;
        packet[7] = ancount & 0xFF;
        packet[8] = (nscount >>> 8) & 0xFF;
        packet[9] = nscount & 0xFF;
        packet[10] = (arcount >>> 8) & 0xFF;
        packet[11] = arcount & 0xFF;

        let pos = 12;

        for (let i = 0; i < qdcount; i++) {
            pos = this.questions[i].write(packet, pos);
        }
        for (let i = 0; i < ancount; i++) {
            pos = this.answers[i].write(packet, pos);
        }
        for (let i = 0; i < nscount; i++) {
            pos = this.authority[i].write(packet, pos);
        }
        for (let i = 0; i < arcount; i++) {
            pos = this.additional[i].write(packet, pos);
        }

        return pos;
    }
}

function makeDNSRequest(domain: string, type: DNS_TYPE) {
    const pkt = new DNSPkt();
    const q = new DNSQuestion();
    q.type = type;
    q.name = domain;
    pkt.questions = [q];
    pkt.id = Math.floor(Math.random() * 0xFFFF);
    return makeDNSUDP(pkt);
}

function makeDNSUDP(dns: DNSPkt) {
    const pkt = new UDPPkt();
    pkt.data = dns.toBytes();
    pkt.sport = 53;
    pkt.dport = 53;
    return pkt;
}

function makeDNSIP() {
    const ip = new IPHdr();
    ip.protocol = IPPROTO.UDP;
    ip.saddr = IP_NONE;
    ip.daddr = getDNSServer();
    ip.df = false;
    return ip;
}

function _makeDNSCacheKey(domain: string, type: DNS_TYPE) {
    return `${type},${domain}`;
}

function domainCB(domain: string, type: number, result: DNSResult) {
    const cacheKey = _makeDNSCacheKey(domain, type);
    if (result) {
        dnsCache.set(cacheKey, result);
    } else {
        dnsCache.delete(cacheKey);
    }

    const queue = dnsQueue.get(cacheKey);
    if (queue) {
        queue.forEach((cb) => { try { cb(result); } catch (e) { logError(e.stack || e); } });
        dnsQueue.delete(cacheKey);
    }

    const timeout = dnsQueueTimeout.get(cacheKey);
    if (timeout) {
        clearTimeout(timeout);
        dnsQueueTimeout.delete(cacheKey);
    }
}

udpListen(53, (data: Uint8Array) => {
    const packet = data.buffer;
    const offset = data.byteOffset;

    const dns = DNSPkt.fromPacket(packet, offset);
    if (!dns || !dns.qr) {
        return;
    }

    const subParseDNSLabel = (pos: number) => {
        return parseDNSLabel({ offset: 0, packet, data, pos });
    };

    // This could clash if asked for ANY, but ANY is deprecated
    const answerMap = new Map<string, DNSAnswer>();
    dns.answers.forEach((a) => {
        if (a.class !== DNS_CLASS.IN) {
            return;
        }

        answerMap.set(a.name, a);
    });

    dns.questions.forEach((q) => {
        if (q.class !== DNS_CLASS.IN) {
            return;
        }

        const domain = q.name;
        let answer = answerMap.get(domain);
        while (answer && answer.type === DNS_TYPE.CNAME && q.type !== DNS_TYPE.CNAME) {
            const cnameTarget = subParseDNSLabel(answer.datapos);
            answer = answerMap.get(cnameTarget);
        }

        if (!answer || answer.type !== q.type) {
            domainCB(domain, q.type, undefined);
            return;
        }

        let cbAnswer;
        switch (q.type) {
            case DNS_TYPE.CNAME:
            case DNS_TYPE.NS:
                cbAnswer = subParseDNSLabel(answer.datapos);
                break;
            case DNS_TYPE.A:
                cbAnswer = IPAddr.fromByteArray(answer.data!);
                break;
        }
        domainCB(domain, q.type, cbAnswer);
    });
});

export function dnsResolve(domain: string, type: DNS_TYPE, cb: DNSCallback) {
    domain = domain.toLowerCase();
    const cacheKey = _makeDNSCacheKey(domain, type);

    if (dnsServerIps.length < 1) {
        cb(undefined);
        return;
    }

    const cache = dnsCache.get(cacheKey);
    if (cache) {
        cb(cache);
        return;
    }

    const queue = dnsQueue.get(cacheKey);
    if (queue) {
        queue.push(cb);
        return;
    }

    dnsQueue.set(cacheKey, [cb]);
    dnsQueueTimeout.set(cacheKey, setTimeout(() => {
        dnsQueueTimeout.delete(cacheKey);
        domainCB(domain, type, undefined);
    }, 10000));

    sendIPPacket(makeDNSIP(), makeDNSRequest(domain, type), INTERFACE_NONE);
}

const IP_REGEX = /^\d+\.\d+\.\d+\.\d+$/;

export function dnsResolveOrIp(domain: string, cb: DNSCallback) {
    if (IP_REGEX.test(domain)) {
        cb(IPAddr.fromString(domain));
        return;
    }

    dnsResolve(domain, DNS_TYPE.A, cb);
}

function recomputeDNSServers() {
    dnsServerIps = [];
    dnsServerIpsByIface.forEach((ips) => {
        ips.forEach((ip) => {
            if (dnsServerIps.findIndex((sIp) => sIp.equals(ip)) >= 0) {
                return;
            }
            dnsServerIps.push(ip);
        });
    });
}

export function addDNSServer(ip: IPAddr, iface: IInterface) {
    let ifaceIps = dnsServerIpsByIface.get(iface);
    if (!ifaceIps) {
        ifaceIps = [];
        dnsServerIpsByIface.set(iface, ifaceIps);
    }

    if (ifaceIps.findIndex((sIp) => sIp.equals(ip)) >= 0) {
        return;
    }
    ifaceIps.push(ip);
    recomputeDNSServers();
}

export function flushDNSServers(iface: IInterface) {
    dnsServerIpsByIface.delete(iface);
    recomputeDNSServers();
}

export function getDNSServer(): IPAddr {
    return dnsServerIps[Math.floor(Math.random() * dnsServerIps.length)];
}

export function getDNSServers(): IPAddr[] {
    return dnsServerIps.slice(0);
}
