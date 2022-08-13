import { IInterface } from "../../../../interface/index";
import { IPAddr } from "../../address";
import { sendPacketTo } from "../../send";
import { UDPPkt } from "../index";
import { udpListen } from "../stack";
import { DNSAnswer } from "./answer";
import { DNS_CLASS, DNS_TYPE, DNSPkt } from "./index";
import { DNSQuestion } from "./question";
import { DNSResult } from "./util";

interface IDNSResolve {
    resolve: (result?: DNSResult) => void;
    reject: (err?: Error) => void;
}

const dnsCache = new Map<string, DNSResult>();
const dnsResolveQueue = new Map<string, IDNSResolve>();
const dnsQueue = new Map<string, Promise<DNSResult | undefined>>();
const dnsQueueTimeout = new Map<string, number>();

let dnsServerIps: IPAddr[] = [];
const dnsServerIpsByIface = new Map<IInterface, IPAddr[]>();

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

function makeDNSCacheKey(domain: string, type: DNS_TYPE) {
    return `${type},${domain}`;
}

function domainCB(domain: string, type: number, result: DNSResult | undefined, err?: Error) {
    const cacheKey = makeDNSCacheKey(domain, type);
    if (result) {
        dnsCache.set(cacheKey, result);
    } else {
        dnsCache.delete(cacheKey);
    }

    const queue = dnsResolveQueue.get(cacheKey);
    if (queue) {
        if (result) {
            queue.resolve(result);
        } else {
            queue.reject(err || new Error("Unknown DNS error"));
        }
        dnsQueue.delete(cacheKey);
        dnsResolveQueue.delete(cacheKey);
    }

    const timeout = dnsQueueTimeout.get(cacheKey);
    if (timeout) {
        clearTimeout(timeout);
        dnsQueueTimeout.delete(cacheKey);
    }
}

class DNSUDPListener {
    public static gotPacket(pkt: UDPPkt) {
        const data = pkt.data;
        if (!data) {
            return;
        }

        const packet = data.buffer;
        const offset = data.byteOffset;

        const dns = DNSPkt.fromPacket(packet as ArrayBuffer, offset);
        if (!dns || !dns.qr) {
            return;
        }

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
                answer = answerMap.get(answer.getData()! as string);
            }

            if (!answer || answer.type !== q.type) {
                domainCB(domain, q.type, undefined, new Error("Invalid DNS answer"));
                return;
            }

            domainCB(domain, q.type, answer.getData());
        });
    }
}

export async function dnsResolve(domain: string, type: DNS_TYPE): Promise<DNSResult | undefined> {
    domain = domain.toLowerCase();
    const cacheKey = makeDNSCacheKey(domain, type);

    if (dnsServerIps.length < 1) {
        throw new Error("Cannot run DNS query without DNS servers");
    }

    const cache = dnsCache.get(cacheKey);
    if (cache) {
        return cache;
    }

    const queue = dnsQueue.get(cacheKey);
    if (queue) {
        return queue;
    }

    const promise = new Promise<DNSResult | undefined>((resolve, reject) => {
        dnsResolveQueue.set(cacheKey, { resolve, reject });
        dnsQueueTimeout.set(cacheKey, setTimeout(() => {
            dnsQueueTimeout.delete(cacheKey);
            domainCB(domain, type, undefined, new Error("Timeout"));
        }, 10000));

        sendPacketTo(getDNSServer(), makeDNSRequest(domain, type));
    });

    dnsQueue.set(cacheKey, promise);

    return promise;
}

const IP_REGEX = /^\d+\.\d+\.\d+\.\d+$/;

export async function dnsResolveOrIp(domain: string) {
    if (IP_REGEX.test(domain)) {
        return IPAddr.fromString(domain);
    }

    return dnsResolve(domain, DNS_TYPE.A);
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

export function removeDNSServer(ip: IPAddr, iface: IInterface) {
    const ifaceIps = dnsServerIpsByIface.get(iface);
    if (!ifaceIps) {
        return;
    }
    const idx = ifaceIps.findIndex((sIp) => sIp.equals(ip));
    if (idx >= 0) {
        ifaceIps.splice(idx, 1);
    }
}

export function clearDNSServers(iface: IInterface) {
    dnsServerIpsByIface.delete(iface);
    recomputeDNSServers();
}

export function getDNSServer(): IPAddr {
    return dnsServerIps[Math.floor(Math.random() * dnsServerIps.length)];
}

export function getDNSServers(iface?: IInterface): IPAddr[] {
    if (iface) {
        return dnsServerIpsByIface.get(iface) || [];
    }
    return dnsServerIps.slice(0);
}

export function enableDNS() {    
    udpListen(53, DNSUDPListener);
}
