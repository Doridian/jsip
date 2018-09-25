import { IPHdr } from "./ip";
import { registerIpHandler } from "./ip_stack";
import { UDPPkt, PROTO_UDP } from "./udp";

type UDPReplyFunc = (data: Uint8Array) => void;
type UDPListener = (data: Uint8Array|undefined, ipHdr: IPHdr, reply: UDPReplyFunc) => void;

const udpListeners: { [key: number]: UDPListener } = {
	7: (data, _ipHdr, reply) => { // ECHO
		if (!data) {
			return;
		}
		reply(data);
	},
};

function udpGotPacket(data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) {
	const udpPkt = UDPPkt.fromPacket(data, offset, len, ipHdr);

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

export function udpListenRandom(func: UDPListener) {
	let port = 0;
	do {
		port = 4097 + Math.floor(Math.random() * 61347);
	} while(udpListeners[port]);

	return udpListen(port, func);
}

export function udpListen(port: number, func: UDPListener) {
	if (typeof port !== 'number' || port < 1 || port > 65535) {
		return false;
	}

	if  (udpListeners[port]) {
		return false;
	}

	udpListeners[port] = func;
	return true;
}

export function udpCloseListener(port: number) {
	if (typeof port !== 'number' || port < 1 || port > 65535) {
		return false;
	}

	if (port === 7) {
		return false;
	}

	delete udpListeners[port];
	return true;
}

registerIpHandler(PROTO_UDP, udpGotPacket);
