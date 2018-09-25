import { IPHdr, IPPROTO } from "./ip";
import { registerIpHandler } from "./ip_stack";
import { UDPPkt } from "./udp";
import { sendPacket } from "./wssend";

type UDPReplyFunc = (data: Uint8Array) => void;
type UDPListener = (data: Uint8Array, ipHdr: IPHdr, reply: UDPReplyFunc) => void;

const udpListeners: { [key: number]: UDPListener } = {
    7: (data, _, reply) => { // ECHO
        if (!data) {
            return;
        }
        reply(data);
    },
};

function udpGotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) {
    const udpPkt = UDPPkt.fromPacket(data, offset, len, ipHdr);

    const listener = udpListeners[udpPkt.dport];
    if (listener && udpPkt.data) {
        return listener(udpPkt.data, ipHdr, (sendData) => {
            const ip = ipHdr.makeReply();
            const udp = new UDPPkt();
            udp.sport = udpPkt.dport;
            udp.dport = udpPkt.sport;
            udp.data = sendData;
            return sendPacket(ip, udp);
        });
    }
}

export function udpListenRandom(func: UDPListener) {
    let port = 0;
    do {
        port = 4097 + Math.floor(Math.random() * 61347);
    } while (udpListeners[port]);

    return udpListen(port, func);
}

export function udpListen(port: number, func: UDPListener) {
    if (typeof port !== "number" || port < 1 || port > 65535) {
        return false;
    }

    if  (udpListeners[port]) {
        return false;
    }

    udpListeners[port] = func;
    return true;
}

export function udpCloseListener(port: number) {
    if (typeof port !== "number" || port < 1 || port > 65535) {
        return false;
    }

    if (port === 7) {
        return false;
    }

    delete udpListeners[port];
    return true;
}

registerIpHandler(IPPROTO.UDP, udpGotPacket);
