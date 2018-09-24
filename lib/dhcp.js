'use strict';

const DHCP_MAGIC = new Uint8Array([0x63, 0x82, 0x53, 0x63]);

class DHCPPkt extends IHdr {
	fill() {
		this.op = 0;
		this.htype = ARP_HTYPE;
		this.hlen = ARP_HLEN;
		this.hops = 0;
		this.xid = 0;
		this.secs = 0;
		this.flags = 0;
		this.ciaddr = null;
		this.yiaddr = null;
		this.siaddr = null;
		this.giaddr = null;
		this.chaddr = null;
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
		dhcp.giaddr = IPAddr.fromByteArray(data, 20);
		dhcp.chaddr = MACAddr.fromByteArray(data, 24);

		if (data[208] !== DHCP_MAGIC[0] || data[209] !== DHCP_MAGIC[1] || data[210] !== DHCP_MAGIC[2] || data[211] !== DHCP_MAGIC[3]) {
			return null;
		}

		let i = 212;
		let gotEnd = false;
		while (i < packet.byteLength) {
			const optId = packet[i];
			if (optId === 0xFF) {
				gotEnd = true;
				break;
			}

			const optLen = packet[i + 1];
			const optVal = new Uint8Array(packet, offset + i + 2, optLen);
			this.options[optId] = optVal;
			i += optLen + 2;
		}

		if (!gotEnd) {
			return null;
		}

		return dhcp;
	}

	getFullLength() {
		let optLen = 1; // 0xFF always needed
		Object.values(this.options).forEach(opt => {
			optLen += 2 + opt.byteLength;
		});
		return 212 + optLen;
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
		this.ciaddr.toBytes(packet, 12);
		this.yiaddr.toBytes(packet, 16);
		this.giaddr.toBytes(packet, 20);
		this.chaddr.toBytes(packet, 24);
		packet[208] = DHCP_MAGIC[0];
		packet[209] = DHCP_MAGIC[1];
		packet[210] = DHCP_MAGIC[2];
		packet[211] = DHCP_MAGIC[3];

		let optPos = 212;
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
