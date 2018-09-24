'use strict';

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

let ourDHCPXID = 0;

const DHCP_OFFSET_MAGIC = 236;

class DHCPPkt extends IHdr {
	fill() {
		this.op = 1;
		this.htype = ARP_HTYPE;
		this.hlen = ARP_HLEN;
		this.hops = 0;
		this.xid = ourDHCPXID;
		this.secs = 0;
		this.flags = 0;
		this.ciaddr = null;
		this.yiaddr = null;
		this.siaddr = null;
		this.giaddr = null;
		this.chaddr = ourMac;
		this.options = {};
	}

	static fromPacket(packet, offset) {
		const data = new Uint8Array(packet, offset);

		const dhcp = new DHCPPkt(false);
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
			const optVal = new Uint8Array(packet, offset + i + 2, optLen);
			dhcp.options[optId] = optVal;
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
		Object.values(this.options).forEach(opt => {
			optLen += 2 + opt.byteLength;
		});
		return DHCP_OFFSET_MAGIC + 4 + optLen;
	}

	toPacket(array, offset) {
		return this._toPacket(new Uint8Array(array, offset));
	}

	toBytes() {
		const packet = new Uint8Array(this.getFullLength());
		this._toPacket(packet, 0);
		return packet;
	}

	_toPacket(packet) {
		packet[0] = this.op;
		packet[1] = this.htype;
		packet[2] = this.hlen;
		packet[3] = this.hops;
		packet[4] = (this.xid >>> 24) & 0xFF;
		packet[5] = (this.xid >>> 16) & 0xFF;
		packet[6] = (this.xid >>> 8) & 0xFF;
		packet[7] = this.xid & 0xFF;
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
		this.chaddr.toBytes(packet, 28);
		packet[DHCP_OFFSET_MAGIC] = DHCP_MAGIC[0];
		packet[DHCP_OFFSET_MAGIC + 1] = DHCP_MAGIC[1];
		packet[DHCP_OFFSET_MAGIC + 2] = DHCP_MAGIC[2];
		packet[DHCP_OFFSET_MAGIC + 3] = DHCP_MAGIC[3];

		let optPos = DHCP_OFFSET_MAGIC + 4;
		Object.entries(this.options).forEach(e => {
			const opt = e[1];
			const optLen = opt.byteLength;
			packet[optPos] = e[0];
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
	pkt.options[DHCP_OPTION_OPTIONS] = new Uint8Array([DHCP_OPTION_ROUTER, DHCP_OPTION_SUBNET, DHCP_OPTION_DNS]);
	return makeDHCPUDP(pkt);
}

function makeDHCPRequest(offer) {
	const pkt = new DHCPPkt();
	pkt.options[DHCP_OPTION_MODE] = new Uint8Array([DHCP_REQUEST]);
	pkt.options[DHCP_OPTION_IP] = offer.yiaddr.toByteArray();
	pkt.options[DHCP_OPTION_SERVER] = offer.siaddr.toByteArray();
	return makeDHCPUDP(pkt);
}

function makeDHCPUDP(dhcp) {
	const pkt = new UDPPkt(false);
	pkt.data = dhcp.toBytes();
	pkt.sport = 68;
	pkt.dport = 67;
	return pkt;
}

function makeDHCPIP() {
	const ip = new IPHdr();
	ip.protocol = PROTO_UDP;
	ip.saddr = IP_NONE;
	ip.daddr = IP_BROADCAST;
	ip.df = true;
	return ip;
}

udpListen(68, (data, ipHdr) => {
	const dhcp = DHCPPkt.fromPacket(data, 0);
	if (!dhcp || dhcp.op !== 2) {
		return;
	}

	if (dhcp.xid !== ourDHCPXID) {
		return;
	}

	switch (dhcp.options[DHCP_OPTION_MODE][0]) {
		case DHCP_OFFER:
			console.log('Got DHCP offer, sending DHCP request...');
			sendPacket(makeDHCPIP(), makeDHCPRequest(dhcp));
			break;
		case DHCP_ACK:
			if (dhcp.options[DHCP_OPTION_IP]) {
				ourIp = IPAddr.fromByteArray(dhcp.options[DHCP_OPTION_IP], 0);
			} else {
				ourIp = dhcp.yiaddr;
			}

			if (dhcp.options[DHCP_OPTION_SUBNET]) {
				const subnet = dhcp.options[DHCP_OPTION_SUBNET];
				ourSubnet = new IPNet(ourIp, subnet[3] + (subnet[2] << 8) + (subnet[1] << 16) + (subnet[0] << 24));
			} else {
				ourSubnet = IPNet.fromString(`${ourIp}/32`);
			}

			if (dhcp.options[DHCP_OPTION_SERVER]) {
				serverIp = IPAddr.fromByteArray(dhcp.options[DHCP_OPTION_SERVER], 0);
			} else {
				serverIp = dhcp.siaddr;
			}

			if (dhcp.options[DHCP_OPTION_ROUTER]) {
				gatewayIp = IPAddr.fromByteArray(dhcp.options[DHCP_OPTION_ROUTER], 0);	
			} else {
				gatewayIp = serverIp;
			}

			if (dhcp.options[DHCP_OPTION_DNS]) {
				// TODO: Multiple
				dnsServerIps = [IPAddr.fromByteArray(dhcp.options[DHCP_OPTION_DNS], 0)];
			} else {
				dnsServerIps = [gatewayIp];
			}

			configOut();
			ourDHCPXID = undefined;

			if (ipDoneCB) {
				ipDoneCB();
				ipDoneCB = undefined;
			}
			break;
		case DHCP_NACK:
			setTimeout(dhcpNegotiate, 0);
			break;
	}
});

function dhcpNegotiate() {
	ourDHCPXID = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
	console.log('DHCP XID', (ourDHCPXID >>> 0).toString(16));
	sendPacket(makeDHCPIP(), makeDHCPDiscover());
}

// TODO: Refresh leases!
