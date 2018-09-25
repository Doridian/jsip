import { config } from './config';
import { registerEthHandler } from './ethernet_stack';
import { EthHdr, ETH_IP, ETH_ARP, ETH_LEN, MACAddr, MAC_BROADCAST } from './ethernet';
import { ARPPkt, ARP_REQUEST, ARP_REPLY, ARP_LEN } from './arp';
import { IPAddr } from './ip';

const arpCache: { [key: string]: MACAddr } = {};
const arpQueue: { [key: string]: [(ethHdr: MACAddr|null) => void] } = {};
const arpTimeouts: { [key: string]: number } = {};

export function makeEthIPHdr(destIp: IPAddr, cb: (ethHdr: EthHdr|null) => void) {
	if (config.ourSubnet && !config.ourSubnet.contains(destIp)) {
		destIp = config.gatewayIp!;
	}

	const destIpStr = destIp.toString();

	const ethHdr = new EthHdr();
	ethHdr.ethtype = ETH_IP;
	ethHdr.saddr = config.ourMac!;
	if (arpCache[destIpStr]) {
		ethHdr.daddr = arpCache[destIpStr];
		cb(ethHdr);
		return;
	}

	if (!destIp.isUnicast()) {
		ethHdr.daddr = MAC_BROADCAST;
		cb(ethHdr);
		return;
	}

	const _cb = (addr: MACAddr|null) => {
		if (!addr) {
			cb(null);
			return;
		}
		ethHdr.daddr = addr;
		cb(ethHdr);
	};

	if (arpQueue[destIpStr]) {
		arpQueue[destIpStr].push(_cb);
		return;
	}

	arpQueue[destIpStr] = [_cb];
	arpTimeouts[destIpStr] = setTimeout(() => {
		delete arpTimeouts[destIpStr];
		if (arpQueue[destIpStr]) {
			arpQueue[destIpStr].forEach(cb => cb(null));
			delete arpQueue[destIpStr];
		}
	}, 10000);

	const arpReq = new ARPPkt();
	arpReq.operation = ARP_REQUEST;
	arpReq.sha = config.ourMac!;
	arpReq.spa = config.ourIp;
	arpReq.tha = MAC_BROADCAST;
	arpReq.tpa = destIp;
	sendARPPkt(arpReq, undefined);
}

function sendARPPkt(arpPkt: ARPPkt, fromAddr: MACAddr|undefined) {
	const pkt = new ArrayBuffer(ETH_LEN + ARP_LEN);

	const ethHdr = new EthHdr();
	ethHdr.daddr = fromAddr || MAC_BROADCAST;
	ethHdr.saddr = config.ourMac;
	ethHdr.ethtype = ETH_ARP;

	ethHdr.toPacket(pkt, 0);
	arpPkt.toPacket(pkt, ETH_LEN);

	config.ws!.send(pkt);
}

function handleARP(buffer: ArrayBuffer, offset: number, ethHdr: EthHdr) {
	const arpPkt = ARPPkt.fromPacket(buffer, offset);
	switch (arpPkt.operation) {
		case ARP_REQUEST:
			if (arpPkt.tpa && arpPkt.tpa.equals(config.ourIp)) {
				const arpReply = arpPkt.makeReply()!;
				sendARPPkt(arpReply, ethHdr.saddr);
			}
			break;
		case ARP_REPLY:
			const ip = arpPkt.spa!.toString();
			const mac = arpPkt.sha!;
			arpCache[ip] = mac;
			if (arpQueue[ip]) {
				arpQueue[ip].forEach(cb => cb(mac));
				delete arpQueue[ip];
			}
			if (arpTimeouts[ip]) {
				clearTimeout(arpTimeouts[ip]);
				delete arpTimeouts[ip];
			}
			break;
	}
}

registerEthHandler(ETH_ARP, handleARP);
