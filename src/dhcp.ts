import { config, configOut } from "./config";
import { ARP_HTYPE, ARP_HLEN } from "./arp";
import { IPAddr, IPHdr, IP_NONE, IP_BROADCAST, IPNet, IPPROTO } from "./ip";
import { MACAddr } from "./ethernet";
import { UDPPkt } from "./udp";
import { udpListen } from "./udp_stack";
import { sendPacket } from "./wssend";

const DHCP_MAGIC = new Uint8Array([0x63, 0x82, 0x53, 0x63]);

const DHCP_OPTION_MODE = 53;
const DHCP_OPTION_SERVER = 54;
const DHCP_OPTION_IP = 50;
const DHCP_OPTION_OPTIONS = 55;
const DHCP_OPTION_SUBNET = 1;
const DHCP_OPTION_ROUTER = 3;
const DHCP_OPTION_DNS = 6;
const DHCP_OPTION_LEASETIME = 51;

const DHCP_DISCOVER = 1;
const DHCP_OFFER = 2;
const DHCP_REQUEST = 3;
const DHCP_ACK = 5;
const DHCP_NACK = 6;

let ourDHCPXID: number|undefined = 0;
let ourDHCPSecs = 0;
let dhcpRenewTimer: number|undefined = undefined;
let dhcpInInitialConfig = false;

const DHCP_OFFSET_MAGIC = 236;

class DHCPPkt {
	public op = 1;
	public htype = ARP_HTYPE;
	public hlen = ARP_HLEN;
	public hops = 0;
	public xid = ourDHCPXID;
	public secs = ourDHCPSecs;
	public flags = 0;
	public ciaddr: IPAddr|undefined = undefined;
	public yiaddr: IPAddr|undefined = undefined;
	public siaddr: IPAddr|undefined = undefined;
	public giaddr: IPAddr|undefined = undefined;
	public chaddr = config.ourMac;
	public options: { [key: string]: Uint8Array } = {};

	static fromPacket(packet: ArrayBuffer, offset: number) {
		const data = new Uint8Array(packet, offset);

		const dhcp = new DHCPPkt();
		dhcp.op = data[0];
		dhcp.htype = data[1];
		dhcp.hlen = data[2];
		dhcp.hops = data[3];
		dhcp.xid = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
		dhcp.secs = data[9] + (data[8] << 8);
		dhcp.flags = data[11] + (data[10] << 8);
		dhcp.ciaddr = IPAddr.fromByteArray(data, 12);
		dhcp.yiaddr = IPAddr.fromByteArray(data, 16);
		dhcp.siaddr = IPAddr.fromByteArray(data, 20);
		dhcp.giaddr = IPAddr.fromByteArray(data, 24);
		dhcp.chaddr = MACAddr.fromByteArray(data, 28);

		if (data[DHCP_OFFSET_MAGIC] !== DHCP_MAGIC[0] || data[DHCP_OFFSET_MAGIC + 1] !== DHCP_MAGIC[1] || data[DHCP_OFFSET_MAGIC + 2] !== DHCP_MAGIC[2] || data[DHCP_OFFSET_MAGIC + 3] !== DHCP_MAGIC[3]) {
			console.error('Invalid DHCP magic');
			return null;
		}

		dhcp.options = {};

		let i = DHCP_OFFSET_MAGIC + 4;
		let gotEnd = false;
		while (i < data.byteLength) {
			const optId = data[i];
			if (optId === 0xFF) {
				gotEnd = true;
				break;
			}

			const optLen = data[i + 1];
			dhcp.options[optId] = new Uint8Array(packet, offset + i + 2, optLen);
			i += optLen + 2;
		}

		if (!gotEnd) {
			console.error('Invalid DHCP end');
			return null;
		}

		return dhcp;
	}

	getFullLength() {
		let optLen = 1; // 0xFF always needed
		Object.keys(this.options).forEach(optK => {
			const opt = this.options[optK];
			optLen += 2 + opt.byteLength;
		});
		return DHCP_OFFSET_MAGIC + 4 + optLen;
	}

	toPacket(array: ArrayBuffer, offset: number) {
		return this._toPacket(new Uint8Array(array, offset));
	}

	toBytes() {
		const packet = new Uint8Array(this.getFullLength());
		this._toPacket(packet);
		return packet;
	}

	_toPacket(packet: Uint8Array) {
		packet[0] = this.op;
		packet[1] = this.htype;
		packet[2] = this.hlen;
		packet[3] = this.hops;
		packet[4] = (this.xid! >>> 24) & 0xFF;
		packet[5] = (this.xid! >>> 16) & 0xFF;
		packet[6] = (this.xid! >>> 8) & 0xFF;
		packet[7] = this.xid! & 0xFF;
		packet[8] = (this.secs >>> 8) & 0xFF;
		packet[9] = this.secs & 0xFF;
		packet[10] = (this.flags >>> 8) & 0xFF;
		packet[11] = this.flags & 0xFF;
		if (this.ciaddr) {
			this.ciaddr.toBytes(packet, 12);
		}
		if (this.yiaddr) {
			this.yiaddr.toBytes(packet, 16);
		}
		if (this.siaddr) {
			this.siaddr.toBytes(packet, 20);
		}
		if (this.giaddr) {
			this.giaddr.toBytes(packet, 24);
		}
		this.chaddr!.toBytes(packet, 28);
		packet[DHCP_OFFSET_MAGIC] = DHCP_MAGIC[0];
		packet[DHCP_OFFSET_MAGIC + 1] = DHCP_MAGIC[1];
		packet[DHCP_OFFSET_MAGIC + 2] = DHCP_MAGIC[2];
		packet[DHCP_OFFSET_MAGIC + 3] = DHCP_MAGIC[3];

		let optPos = DHCP_OFFSET_MAGIC + 4;
		Object.keys(this.options).forEach(optId => {
			const opt = this.options[optId];
			const optLen = opt.byteLength;
			packet[optPos] = parseInt(optId, 10);
			packet[optPos + 1] = optLen;
			for (let i = 0; i < optLen; i++) {
				packet[optPos + 2 + i] = opt[i];
			}
			optPos += 2 + opt.byteLength;
		});
		packet[optPos] = 0xFF;

		return optPos;
	}
}

function makeDHCPDiscover() {
	const pkt = new DHCPPkt();
	pkt.options[DHCP_OPTION_MODE] = new Uint8Array([DHCP_DISCOVER]);
	pkt.options[DHCP_OPTION_OPTIONS] = new Uint8Array([
		DHCP_OPTION_ROUTER,
		DHCP_OPTION_SUBNET,
		DHCP_OPTION_DNS,
		DHCP_OPTION_LEASETIME,
		DHCP_OPTION_SERVER,
		DHCP_OPTION_IP,
	]);
	return makeDHCPUDP(pkt);
}

function makeDHCPRequest(offer: DHCPPkt) {
	const pkt = new DHCPPkt();
	pkt.options[DHCP_OPTION_MODE] = new Uint8Array([DHCP_REQUEST]);
	pkt.options[DHCP_OPTION_IP] = offer.yiaddr!.toByteArray();
	pkt.options[DHCP_OPTION_SERVER] = offer.siaddr!.toByteArray();
	return makeDHCPUDP(pkt);
}

function makeDHCPRenewRequest() {
	const pkt = new DHCPPkt();
	pkt.options[DHCP_OPTION_MODE] = new Uint8Array([DHCP_REQUEST]);
	pkt.options[DHCP_OPTION_IP] = config.ourIp!.toByteArray();
	pkt.options[DHCP_OPTION_SERVER] = config.serverIp!.toByteArray();
	return makeDHCPUDP(pkt);
}

function makeDHCPUDP(dhcp: DHCPPkt) {
	const pkt = new UDPPkt();
	pkt.data = dhcp.toBytes();
	pkt.sport = 68;
	pkt.dport = 67;
	return pkt;
}

function makeDHCPIP(unicast: boolean = false) {
	const ip = new IPHdr();
	ip.protocol = IPPROTO.UDP;
	if (unicast) {
		ip.saddr = config.ourIp;
		ip.daddr = config.serverIp;
	} else {
		ip.saddr = IP_NONE;
		ip.daddr = IP_BROADCAST;
	}
	ip.df = true;
	return ip;
}

udpListen(68, (data: Uint8Array|undefined, _ipHdr: IPHdr) => {
	if (!data) {
		return;
	}

	const packet = data.buffer;
	const offset = data.byteOffset;

	const dhcp = DHCPPkt.fromPacket(packet, offset);
	if (!dhcp || dhcp.op !== 2) {
		return;
	}

	if (dhcp.xid !== ourDHCPXID) {
		return;
	}

	if (dhcpRenewTimer !== undefined) {
		clearTimeout(dhcpRenewTimer);
		dhcpRenewTimer = undefined;
	}

	switch (dhcp.options[DHCP_OPTION_MODE][0]) {
		case DHCP_OFFER:
			console.log('Got DHCP offer, sending DHCP request...');
			sendPacket(makeDHCPIP(), makeDHCPRequest(dhcp));
			break;
		case DHCP_ACK:
			if (dhcp.options[DHCP_OPTION_IP]) {
				config.ourIp = IPAddr.fromByteArray(dhcp.options[DHCP_OPTION_IP], 0);
			} else {
				config.ourIp = dhcp.yiaddr;
			}

			if (dhcp.options[DHCP_OPTION_SUBNET]) {
				const subnet = dhcp.options[DHCP_OPTION_SUBNET];
				config.ourSubnet = new IPNet(config.ourIp!, subnet[3] + (subnet[2] << 8) + (subnet[1] << 16) + (subnet[0] << 24));
			} else {
				config.ourSubnet = IPNet.fromString(`${config.ourIp}/32`);
			}

			if (dhcp.options[DHCP_OPTION_SERVER]) {
				config.serverIp = IPAddr.fromByteArray(dhcp.options[DHCP_OPTION_SERVER], 0);
			} else {
				config.serverIp = dhcp.siaddr;
			}

			if (dhcp.options[DHCP_OPTION_ROUTER]) {
				config.gatewayIp = IPAddr.fromByteArray(dhcp.options[DHCP_OPTION_ROUTER], 0);	
			} else {
				config.gatewayIp = config.serverIp;
			}

			if (dhcp.options[DHCP_OPTION_DNS]) {
				// TODO: Multiple
				config.dnsServerIps = [IPAddr.fromByteArray(dhcp.options[DHCP_OPTION_DNS], 0)];
			} else {
				config.dnsServerIps = [config.gatewayIp!];
			}

			let ttl;
			if (dhcp.options[DHCP_OPTION_LEASETIME]) {
				const _ttl = dhcp.options[DHCP_OPTION_LEASETIME];
				ttl = (_ttl[3] + (_ttl[2] << 8) + (_ttl[1] << 16) + (_ttl[0] << 24)) >>> 0;
			} else {
				ttl = 300;
			}

			if (dhcpInInitialConfig) {
				dhcpInInitialConfig = false;
				configOut();
			}
			ourDHCPXID = undefined;

			console.log(`DHCP TTL: ${ttl}`);
			const __ttl = ((ttl * 1000) / 2) + 1000;
			dhcpRenewTimer = setTimeout(dhcpRenew, __ttl, (ttl * 1000) - __ttl);

			if (config.ipDoneCB) {
				config.ipDoneCB();
				config.ipDoneCB = undefined;
			}
			break;
		case DHCP_NACK:
			setTimeout(dhcpNegotiate, 0);
			break;
	}
});

export function dhcpNegotiate(secs = 0) {
	dhcpInInitialConfig = true;
	if (dhcpRenewTimer !== undefined) {
		clearTimeout(dhcpRenewTimer);
		dhcpRenewTimer = undefined;
	}

	if (secs === 0) {
		ourDHCPXID = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
		console.log('DHCP Initial XID', (ourDHCPXID >>> 0).toString(16));
	} else {
		console.log(`DHCP Initial retry: secs = ${secs}`);
	}
	ourDHCPSecs = secs;

	dhcpRenewTimer = setTimeout(dhcpNegotiate, 5000, secs + 5);
	sendPacket(makeDHCPIP(), makeDHCPDiscover());
}

function dhcpRenew(__ttl: number = 0) {
	if (__ttl) {
		dhcpRenewTimer = setTimeout(dhcpNegotiate, __ttl);
	}

	ourDHCPSecs = 0;
	ourDHCPXID = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
	console.log('DHCP Renew XID', (ourDHCPXID >>> 0).toString(16));
	sendPacket(makeDHCPIP(true), makeDHCPRenewRequest());
}
