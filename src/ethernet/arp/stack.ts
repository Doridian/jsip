import { IInterface } from "../../interface/index.js";
import { INTERFACE_NONE } from "../../interface/none.js";
import { MAC_BROADCAST, MACAddr } from "../address.js";
import { ETH_LEN, ETH_TYPE, EthHdr } from "../index.js";
import { IPAddr } from "../ip/address.js";
import { registerEthHandler } from "../stack.js";
import { ARP_LEN, ARP_REPLY, ARP_REQUEST, ARPPkt } from "./index.js";

interface IARPResolve {
    resolve: (mac: MACAddr) => void;
    reject: (err: Error) => void;
}

const arpCache = new Map<number, MACAddr>();
const arpQueue = new Map<number, Promise<EthHdr>>();
const arpResolveQueue = new Map<number, IARPResolve>();
const arpTimeouts = new Map<number, number>();

export async function makeEthIPHdr(destIp: IPAddr, iface: IInterface = INTERFACE_NONE): Promise<EthHdr> {
    const ethHdr = new EthHdr();
    ethHdr.ethtype = ETH_TYPE.IP;
    ethHdr.saddr = iface.getMAC();

    if (!destIp.isUnicast()) {
        ethHdr.daddr = MAC_BROADCAST;
        return ethHdr;
    }

    if (iface === INTERFACE_NONE) {
        throw new Error("Cannot make ETH header for none interface");
    }

    const destIpKey = destIp.toInt32();

    const cacheValue = arpCache.get(destIpKey);
    if (cacheValue) {
        ethHdr.daddr = cacheValue;
        return ethHdr;
    }

    const ourIp = iface.getIP();

    if (destIp.isLoopback() || destIp.equals(ourIp)) {
        ethHdr.daddr = ethHdr.saddr;
        return ethHdr;
    }

    let promise = arpQueue.get(destIpKey);
    if (promise) {
        return promise;
    }

    promise = new Promise<MACAddr>((resolve, reject) => {
        arpResolveQueue.set(destIpKey, { resolve, reject });
    }).then((macAddr) => {
        ethHdr.daddr = macAddr;
        return ethHdr;
    });

    arpTimeouts.set(destIpKey, setTimeout(() => {
        arpTimeouts.delete(destIpKey);
        const timeoutQueue = arpResolveQueue.get(destIpKey);
        if (timeoutQueue) {
            timeoutQueue.reject(new Error("Timeout"));
            arpResolveQueue.delete(destIpKey);
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

    return promise;
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

class EthARPListener {
    public static gotPacket(buffer: ArrayBuffer, offset: number, ethHdr: EthHdr, iface: IInterface) {
        const arpPkt = ARPPkt.fromPacket(buffer, offset);
        switch (arpPkt.operation) {
            case ARP_REQUEST:
                if (arpPkt.tpa && arpPkt.tpa.equals(iface.getIP())) {
                    sendARPPkt(arpPkt.makeReply()!, ethHdr.saddr, iface);
                }
                break;
            case ARP_REPLY:
                const ip = arpPkt.spa.toInt32();
                const mac = arpPkt.sha;

                arpCache.set(ip, mac);

                const queue = arpResolveQueue.get(ip);
                if (queue) {
                    queue.resolve(mac);
                    arpResolveQueue.delete(ip);
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
}

registerEthHandler(ETH_TYPE.ARP, EthARPListener);
