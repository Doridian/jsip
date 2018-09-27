import { IPHdr, IPPROTO } from "../index";
import { sendIPPacket } from "../send";
import { registerIpHandler } from "../stack";
import { UDPPkt } from "./index";

type UDPReplyFunc = (data: Uint8Array) => void;
type UDPListener = (data: Uint8Array, ipHdr: IPHdr, reply: UDPReplyFunc) => void;

const udpListeners = new Map<number, UDPListener>();
udpListeners.set(
    7,
    (data, _, reply) => { // ECHO
        if (!data) {
            return;
        }
        reply(data);
    },
);

function udpGotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) {
    const udpPkt = UDPPkt.fromPacket(data, offset, len, ipHdr);

    const listener = udpListeners.get(udpPkt.dport);
    if (listener && udpPkt.data) {
        return listener(udpPkt.data, ipHdr, (sendData) => {
            const ip = ipHdr.makeReply();
            const udp = new UDPPkt();
            udp.sport = udpPkt.dport;
            udp.dport = udpPkt.sport;
            udp.data = sendData;
            return sendIPPacket(ip, udp);
        });
    }
}

export function udpListenRandom(func: UDPListener) {
    let port = 0;
    do {
        port = 4097 + Math.floor(Math.random() * 61347);
    } while (udpListeners.has(port));

    return udpListen(port, func);
}

export function udpListen(port: number, func: UDPListener) {
    if (port < 1 || port > 65535) {
        return false;
    }

    if  (udpListeners.has(port)) {
        return false;
    }

    udpListeners.set(port, func);
    return true;
}

export function udpCloseListener(port: number) {
    if (port < 1 || port > 65535) {
        return false;
    }

    if (port === 7) {
        return false;
    }

    udpListeners.delete(port);
    return true;
}

registerIpHandler(IPPROTO.UDP, udpGotPacket);
