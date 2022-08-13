import { IInterface } from "../../../interface/index";
import { logError } from "../../../util/log";
import { IPHdr, IPPROTO } from "../index";
import { sendIPPacket } from "../send";
import { registerIpHandler } from "../stack";
import { UDPPkt } from "./index";

export type UDPReplyFunc = (data: Uint8Array) => void;
export interface IUDPListener {
    gotPacket(pkt: UDPPkt, ip: IPHdr, iface: IInterface): Uint8Array | PromiseLike<Uint8Array> |
                                                          undefined | PromiseLike<undefined> |
                                                          void | PromiseLike<void>;
}

const udpListeners = new Map<number, IUDPListener>();

class UDPEchoListener {
    public static gotPacket(pkt: UDPPkt, _: IPHdr, __: IInterface) {
        if (pkt.sport === 7) {
            return;
        }
        return pkt.data;
    }
}

// tslint:disable-next-line:max-classes-per-file
class IPUDPListener {
    public static gotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr, iface: IInterface) {
        const udpPkt = UDPPkt.fromPacket(data, offset, len, ipHdr);

        const listener = udpListeners.get(udpPkt.dport);
        if (listener && udpPkt.data) {
            try {
                Promise.resolve<Uint8Array | undefined | void>(listener.gotPacket(udpPkt, ipHdr, iface))
                .then((reply?: Uint8Array | void) => {
                    if (!reply) {
                        return;
                    }

                    const ip = ipHdr.makeReply();
                    const udp = new UDPPkt();
                    udp.sport = udpPkt.dport;
                    udp.dport = udpPkt.sport;
                    udp.data = reply;
                    return sendIPPacket(ip, udp, iface);
                })
                .catch(logError);
            } catch (e) {
                logError(e as Error);
            }
        }
    }
}

export function udpListenRandom(func: IUDPListener) {
    let port = 0;
    do {
        port = 4097 + Math.floor(Math.random() * 61347);
    } while (udpListeners.has(port));

    return udpListen(port, func);
}

export function udpListen(port: number, func: IUDPListener) {
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

export function enableUDP() {
    udpListeners.set(7, UDPEchoListener);

    registerIpHandler(IPPROTO.UDP, IPUDPListener);
}

