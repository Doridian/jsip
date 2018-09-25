'use strict';

const icmpHandlers = {};

function icmpGotPacket(data, offset, len, ipHdr) {
	const icmpPkt = ICMPPkt.fromPacket(data, offset, len);

	const handler = icmpHandlers[icmpPkt.type];
	if (handler) {
		handler(icmpPkt, ipHdr);
	}
}

function icmpHandleEchoRequest(icmpPkt, ipHdr) {
	const replyIp = ipHdr.makeReply();

	const replyICMP = new ICMPPkt();
	replyICMP.type = 0;
	replyICMP.code = 0;
	replyICMP.rest = icmpPkt.rest;
	replyICMP.data = icmpPkt.data;

	sendPacket(replyIp, replyICMP);
}

function registerICMPHandler(type, handler) {
	icmpHandlers[type] = handler;
}

registerICMPHandler(8, icmpHandleEchoRequest);

registerIpHandler(PROTO_ICMP, icmpGotPacket);
