import { IInterface } from "../../../interface/index";
import { IPHdr, IPPROTO } from "../index";
import { sendIPPacket } from "../send";
import { registerIpHandler } from "../stack";
import { ICMPPkt } from "./index";

export interface IICMPHandler {
    gotPacket(icmpPkt: ICMPPkt, ipHdr: IPHdr, iface: IInterface): void;
}

const icmpHandlers = new Map<number, IICMPHandler>();

class IPICMPListener {
    public static gotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr, iface: IInterface) {
        const icmpPkt = ICMPPkt.fromPacket(data, offset, len);

        const handler = icmpHandlers.get(icmpPkt.type);
        if (handler) {
            handler.gotPacket(icmpPkt, ipHdr, iface);
        }
    }
}

// tslint:disable-next-line:max-classes-per-file
class ICMPEchoRequestListener {
    public static gotPacket(icmpPkt: ICMPPkt, ipHdr: IPHdr, iface: IInterface) {
        const replyIp = ipHdr.makeReply();

        const replyICMP = new ICMPPkt();
        replyICMP.type = 0;
        replyICMP.code = 0;
        replyICMP.rest = icmpPkt.rest;
        replyICMP.data = icmpPkt.data;

        sendIPPacket(replyIp, replyICMP, iface);
    }
}

export function registerICMPHandler(type: number, handler: IICMPHandler) {
    icmpHandlers.set(type, handler);
}

export function enableICMP() {
    registerICMPHandler(8, ICMPEchoRequestListener);
    registerIpHandler(IPPROTO.ICMP, IPICMPListener);
}
