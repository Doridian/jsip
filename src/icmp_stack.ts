import { ICMPPkt } from "./icmp";
import { IPHdr } from "./ip";
import { registerIpHandler } from "./ip_stack";
import { sendPacket } from "./wssend";

type ICMPHandler = (icmpPkt: ICMPPkt, ipHdr: IPHdr) => void;

const icmpHandlers: { [key: number]: ICMPHandler } = {};

export const PROTO_ICMP = 1;

function icmpGotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) {
	const icmpPkt = ICMPPkt.fromPacket(data, offset, len);

	const handler = icmpHandlers[icmpPkt.type];
	if (handler) {
		handler(icmpPkt, ipHdr);
	}
}

function icmpHandleEchoRequest(icmpPkt: ICMPPkt, ipHdr: IPHdr) {
	const replyIp = ipHdr.makeReply();

	const replyICMP = new ICMPPkt();
	replyICMP.type = 0;
	replyICMP.code = 0;
	replyICMP.rest = icmpPkt.rest;
	replyICMP.data = icmpPkt.data;

	sendPacket(replyIp, replyICMP);
}

function registerICMPHandler(type: number, handler: ICMPHandler) {
	icmpHandlers[type] = handler;
}

registerICMPHandler(8, icmpHandleEchoRequest);

registerIpHandler(PROTO_ICMP, icmpGotPacket);
