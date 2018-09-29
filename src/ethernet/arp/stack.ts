import { IInterface } from "../../interface/index.js";
import { INTERFACE_NONE } from "../../interface/none.js";
import { logError } from "../../util/log.js";
import { MAC_BROADCAST, MACAddr } from "../address.js";
import { ETH_LEN, ETH_TYPE, EthHdr } from "../index.js";
import { IPAddr } from "../ip/address.js";
import { registerEthHandler } from "../stack.js";
import { ARP_LEN, ARP_REPLY, ARP_REQUEST, ARPPkt } from "./index.js";

type ARPCallback = (ethHdr?: MACAddr) => void;

const arpCache = new Map<number, MACAddr>();
const arpQueue = new Map<number, ARPCallback[]>();
const arpTimeouts = new Map<number, number>();

export function makeEthIPHdr(destIp: IPAddr, cb: (ethHdr?: EthHdr) => void, iface: IInterface = INTERFACE_NONE) {
    const ethHdr = new EthHdr();
    ethHdr.ethtype = ETH_TYPE.IP;
    ethHdr.saddr = iface.getMAC();

    if (!destIp.isUnicast()) {
        ethHdr.daddr = MAC_BROADCAST;
        cb(ethHdr);
        return;
    }

    if (iface === INTERFACE_NONE) {
        cb();
        return;
    }

    const destIpKey = destIp.toInt();

    const cacheValue = arpCache.get(destIpKey);
    if (cacheValue) {
        ethHdr.daddr = cacheValue;
        cb(ethHdr);
        return;
    }

    const ourIp = iface.getIP();

    if (destIp.isLoopback() || destIp.equals(ourIp)) {
        ethHdr.daddr = ethHdr.saddr;
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
    arpReq.sha = ethHdr.saddr;
    arpReq.spa = ourIp;
    arpReq.tha = MAC_BROADCAST;
    arpReq.tpa = destIp;
    sendARPPkt(arpReq, MAC_BROADCAST, iface);
}

function sendARPPkt(arpPkt: ARPPkt, fromAddr: MACAddr, iface: IInterface) {
    const pkt = new ArrayBuffer(ETH_LEN + ARP_LEN);

    const ethHdr = new EthHdr();
    ethHdr.daddr = fromAddr;
    ethHdr.saddr = iface.getMAC();
    ethHdr.ethtype = ETH_TYPE.ARP;

    ethHdr.toPacket(pkt, 0);
    arpPkt.toPacket(pkt, ETH_LEN);

    iface.sendRaw(pkt);
}

function handleARP(buffer: ArrayBuffer, offset: number, ethHdr: EthHdr, iface: IInterface) {
    const arpPkt = ARPPkt.fromPacket(buffer, offset);
    switch (arpPkt.operation) {
        case ARP_REQUEST:
            if (arpPkt.tpa && arpPkt.tpa.equals(iface.getIP())) {
                sendARPPkt(arpPkt.makeReply()!, ethHdr.saddr, iface);
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
