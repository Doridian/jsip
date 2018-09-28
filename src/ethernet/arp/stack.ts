import { config } from "../../config";
import { logError } from "../../util/log";
import { sendRaw } from "../../wsvpn";
import { MAC_BROADCAST, MACAddr } from "../address";
import { ETH_LEN, ETH_TYPE, EthHdr } from "../index";
import { IP_NONE, IPAddr } from "../ip/address";
import { getRoute } from "../ip/router";
import { registerEthHandler } from "../stack";
import { ARP_LEN, ARP_REPLY, ARP_REQUEST, ARPPkt } from "./index";

type ARPCallback = (ethHdr?: MACAddr) => void;

const arpCache = new Map<number, MACAddr>();
const arpQueue = new Map<number, ARPCallback[]>();
const arpTimeouts = new Map<number, number>();

export function makeEthIPHdr(destIp: IPAddr, cb: (ethHdr?: EthHdr) => void) {
    const router = getRoute(destIp);
    if (router !== IP_NONE) {
        if (!router) {
            cb();
            return;
        }
        destIp = router;
    }

    const destIpKey = destIp.toInt();

    const ethHdr = new EthHdr();
    ethHdr.ethtype = ETH_TYPE.IP;
    ethHdr.saddr = config.ourMac;

    const cacheValue = arpCache.get(destIpKey);
    if (cacheValue) {
        ethHdr.daddr = cacheValue;
        cb(ethHdr);
        return;
    }

    if (!destIp.isUnicast()) {
        ethHdr.daddr = MAC_BROADCAST;
        cb(ethHdr);
        return;
    }

    if (destIp.isLoopback() || destIp.equals(config.ourIp)) {
        ethHdr.daddr = config.ourMac;
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

    const queue = arpQueue.get(destIpKey);
    if (queue) {
        queue.push(cbTmp);
        return;
    }

    arpQueue.set(destIpKey, [cbTmp]);
    arpTimeouts.set(destIpKey, setTimeout(() => {
        arpTimeouts.delete(destIpKey);
        const timeoutQueue = arpQueue.get(destIpKey);
        if (timeoutQueue) {
            timeoutQueue.forEach((queueCb) => { try { queueCb(); } catch (e) { logError(e.stack || e); } });
            arpQueue.delete(destIpKey);
        }
    }, 10000));

    const arpReq = new ARPPkt();
    arpReq.operation = ARP_REQUEST;
    arpReq.sha = config.ourMac;
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

    sendRaw(pkt);
}

function handleARP(buffer: ArrayBuffer, offset: number, ethHdr: EthHdr) {
    const arpPkt = ARPPkt.fromPacket(buffer, offset);
    switch (arpPkt.operation) {
        case ARP_REQUEST:
            if (arpPkt.tpa && arpPkt.tpa.equals(config.ourIp)) {
                sendARPPkt(arpPkt.makeReply()!, ethHdr.saddr);
            }
            break;
        case ARP_REPLY:
            const ip = arpPkt.spa.toInt();
            const mac = arpPkt.sha;

            arpCache.set(ip, mac);

            const queue = arpQueue.get(ip);
            if (queue) {
                queue.forEach((cb) => { try { cb(mac); } catch (e) { logError(e.stack || e); } });
                arpQueue.delete(ip);
            }
            const timeout = arpTimeouts.get(ip);
            if (timeout) {
                clearTimeout(timeout);
                arpTimeouts.delete(ip);
            }
            break;
    }
}

registerEthHandler(ETH_TYPE.ARP, handleARP);
