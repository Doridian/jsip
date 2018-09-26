import { ARP_LEN, ARP_REPLY, ARP_REQUEST, ARPPkt } from "./arp";
import { config } from "./config";
import { ETH_LEN, ETH_TYPE, EthHdr } from "./ethernet";
import { MAC_BROADCAST, MACAddr } from "./ethernet_addr";
import { registerEthHandler } from "./ethernet_stack";
import { IPAddr } from "./ip_addr";

type ARPCallback = (ethHdr?: MACAddr) => void;

const arpCache: { [key: string]: MACAddr } = {};
const arpQueue: { [key: string]: ARPCallback[] } = {};
const arpTimeouts: { [key: string]: number } = {};

export function makeEthIPHdr(destIp: IPAddr, cb: (ethHdr?: EthHdr) => void) {
    if (config.ourSubnet && !config.ourSubnet.contains(destIp)) {
        destIp = config.gatewayIp!;
    }

    const destIpStr = destIp.toString();

    const ethHdr = new EthHdr();
    ethHdr.ethtype = ETH_TYPE.IP;
    ethHdr.saddr = config.ourMac!;
    if (arpCache[destIpStr]) {
        ethHdr.daddr = arpCache[destIpStr];
        cb(ethHdr);
        return;
    }

    if (!destIp.isUnicast()) {
        ethHdr.daddr = MAC_BROADCAST;
        cb(ethHdr);
        return;
    }

    const cbTmp = (addr?: MACAddr) => {
        if (!addr) {
            cb();
            return;
        }
        ethHdr.daddr = addr;
        cb(ethHdr);
    };

    if (arpQueue[destIpStr]) {
        arpQueue[destIpStr].push(cbTmp);
        return;
    }

    arpQueue[destIpStr] = [cbTmp];
    arpTimeouts[destIpStr] = setTimeout(() => {
        delete arpTimeouts[destIpStr];
        if (arpQueue[destIpStr]) {
            arpQueue[destIpStr].forEach((queueCb) => queueCb());
            delete arpQueue[destIpStr];
        }
    }, 10000);

    const arpReq = new ARPPkt();
    arpReq.operation = ARP_REQUEST;
    arpReq.sha = config.ourMac!;
    arpReq.spa = config.ourIp;
    arpReq.tha = MAC_BROADCAST;
    arpReq.tpa = destIp;
    sendARPPkt(arpReq);
}

function sendARPPkt(arpPkt: ARPPkt, fromAddr?: MACAddr) {
    const pkt = new ArrayBuffer(ETH_LEN + ARP_LEN);

    const ethHdr = new EthHdr();
    ethHdr.daddr = fromAddr || MAC_BROADCAST;
    ethHdr.saddr = config.ourMac;
    ethHdr.ethtype = ETH_TYPE.ARP;

    ethHdr.toPacket(pkt, 0);
    arpPkt.toPacket(pkt, ETH_LEN);

    config.ws!.send(pkt);
}

function handleARP(buffer: ArrayBuffer, offset: number, ethHdr: EthHdr) {
    const arpPkt = ARPPkt.fromPacket(buffer, offset);
    switch (arpPkt.operation) {
        case ARP_REQUEST:
            if (arpPkt.tpa && arpPkt.tpa.equals(config.ourIp)) {
                const arpReply = arpPkt.makeReply()!;
                sendARPPkt(arpReply, ethHdr.saddr);
            }
            break;
        case ARP_REPLY:
            const ip = arpPkt.spa!.toString();
            const mac = arpPkt.sha!;
            arpCache[ip] = mac;
            if (arpQueue[ip]) {
                arpQueue[ip].forEach((cb) => cb(mac));
                delete arpQueue[ip];
            }
            if (arpTimeouts[ip]) {
                clearTimeout(arpTimeouts[ip]);
                delete arpTimeouts[ip];
            }
            break;
    }
}

registerEthHandler(ETH_TYPE.ARP, handleARP);
