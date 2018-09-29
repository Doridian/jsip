import { IInterface } from "../../../interface/index.js";
import { IPHdr, IPPROTO } from "../index.js";
import { sendIPPacket } from "../send.js";
import { registerIpHandler } from "../stack.js";
import { ICMPPkt } from "./index.js";

type ICMPHandler = (icmpPkt: ICMPPkt, ipHdr: IPHdr, iface: IInterface) => void;

const icmpHandlers = new Map<number, ICMPHandler>();

function icmpGotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr, iface: IInterface) {
    const icmpPkt = ICMPPkt.fromPacket(data, offset, len);

    const handler = icmpHandlers.get(icmpPkt.type);
    if (handler) {
        handler(icmpPkt, ipHdr, iface);
    }
}

function icmpHandleEchoRequest(icmpPkt: ICMPPkt, ipHdr: IPHdr, iface: IInterface) {
    const replyIp = ipHdr.makeReply();

    const replyICMP = new ICMPPkt();
    replyICMP.type = 0;
    replyICMP.code = 0;
    replyICMP.rest = icmpPkt.rest;
    replyICMP.data = icmpPkt.data;

    sendIPPacket(replyIp, replyICMP, iface);
}

function registerICMPHandler(type: number, handler: ICMPHandler) {
    icmpHandlers.set(type, handler);
}

registerICMPHandler(8, icmpHandleEchoRequest);

registerIpHandler(IPPROTO.ICMP, icmpGotPacket);
