'use strict';

const udpListeners = {
	7: (data, ipHdr, reply) => { // ECHO
		reply(data);
	},
};

function udpGotPacket(ipHdr, udpPkt) {
	const listener = udpListeners[udpPkt.dport];
	if (listener) {
		return listener(udpPkt.data, ipHdr, data => {
			const ip = ipHdr.makeReply();
			const udp = new UDPPkt();
			udp.sport = udpPkt.dport;
			udp.dport = udpPkt.sport;
			udp.data = data;
			return sendPacket(ip, udp);
		});
	}
}
