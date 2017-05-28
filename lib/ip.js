'use strict';

class IPAddr {
	static fromString(ipStr) {
		const ip = new IPAddr();
		const ipS = ipStr.split('.');
		ip.a = parseInt(ipS[0]);
		ip.b = parseInt(ipS[1]);
		ip.c = parseInt(ipS[2]);
		ip.d = parseInt(ipS[3]);
		return ip;
	}

	static fromByteArray(ipBytes) {
		const ip = new IPAddr();
		ip.a = ipBytes[0];
		ip.b = ipBytes[1];
		ip.c = ipBytes[2];
		ip.d = ipBytes[3];
		return ip;
	}

	static fromBytes(a, b, c, d) {
		const ip = new IPAddr();
		ip.a = a;
		ip.b = b;
		ip.c = c;
		ip.d = d;
		return ip;
	}

	static fromInt32(ipInt) {
		const ip = new IPAddr();
		ip.a = ipInt & 0xFF;
		ip.b = (ipInt >>> 8) & 0xFF;
		ip.c = (ipInt >>> 16) & 0xFF;
		ip.d = (ipInt >>> 24) & 0xFF;
		return ip;
	}

	equals(ip) {
		return ip.a === this.a && ip.b === this.b && ip.c === this.c && ip.d === this.d;
	}

	toBytes(array, offset) {
		array[offset] = this.a;
		array[offset + 1] = this.b;
		array[offset + 2] = this.c;
		array[offset + 3] = this.d;
	}

	toString() {
		return `${this.a}.${this.b}.${this.c}.${this.d}`;
	}
}

class IPHdr extends IHdr {
	fill() {
		this.version = 4;
		this.ihl = 5;
		this.dscp = 0;
		this.ecn = 0;
		this.len = 0;
		this.id = 0;
		this.df = false;
		this.mf = false;
		this.frag_offset = 0;
		this.ttl = 64;
		this.protocol = 0;
		this.checksum = 0;
		this.saddr = null;
		this.daddr = null;
		this.options = new ArrayBuffer(0);
	}

	static fromPacket(packet, offset) {
		const ipv4 = new IPHdr(false);
		const bit = new BitArray(packet, offset);
		ipv4.version = bit.read(4);
		ipv4.ihl = bit.read(4);
		ipv4.dscp = bit.read(6);
		ipv4.ecn = bit.read(2);
		ipv4.len = bit.read(16);
		ipv4.id = bit.read(16);
		const flags = bit.read(3);
		ipv4.df = (flags & 0x2) === 0x2;
		ipv4.mf = (flags & 0x1) === 0x1;
		ipv4.frag_offset = bit.read(13);
		ipv4.ttl = bit.read(8);
		ipv4.protocol = bit.read(8);
		ipv4.checksum = bit.read(16);
		ipv4.saddr = IPAddr.fromBytes(bit.read(8), bit.read(8), bit.read(8), bit.read(8));
		ipv4.daddr = IPAddr.fromBytes(bit.read(8), bit.read(8), bit.read(8), bit.read(8));
		const oLen = ipv4.ihl << 2;
		if (oLen > 20) {
			ipv4.options = packet.slice((bit.pos >>> 3) + offset, oLen - 20);
		} else {
			ipv4.options = new ArrayBuffer(0);
		}
		if (computeChecksum(packet, 0, oLen) !== 0) {
			throw new Error('Invalid IPv4 checksum');
		}
		return ipv4;
	}

	setContentLength(len) {
		this.len = this.getContentOffset() + len;
	}

	getContentLength() {
		return this.len - this.getContentOffset();
	}

	getFullLength() {
		return this.len;
	}

	getContentOffset() {
		return this.ihl << 2;
	}

	toPacket(array, offset) {
		const packet = new Uint8Array(array, offset, this.options.byteLength + 20);
		this.ihl = packet.length >>> 2;
		packet[0] = ((this.version & 0xF) << 4) + (this.ihl & 0xF);
		packet[1] = ((this.dscp & 0xFC) << 2) + (this.ecn & 0x3);
		packet[2] = (this.len >>> 8) & 0xFF;
		packet[3] = this.len & 0xFF;
		packet[4] = (this.id >>> 8) & 0xFF;
		packet[5] = this.id & 0xFF;
		const flags = (this.df ? 0x2 : 0x0) + (this.mf ? 0x1 : 0x0);
		packet[6] = (flags << 5) + ((this.frag_offset >>> 8) & 0x1F);
		packet[7] = this.frag_offset & 0xFF;
		packet[8] = this.ttl & 0xFF;
		packet[9] = this.protocol & 0xFF;
		packet[10] = 0; // Checksum A
		packet[11] = 0; // Checksum B
		this.saddr.toBytes(packet, 12);
		this.daddr.toBytes(packet, 16);
		if (this.options.byteLength > 0) {
			const o8 = new Uint8Array(this.options);
			for (let i = 0; i < o8.length; i++) {
				packet[i + 12] = o8[i];
			}
		}
		this.checksum = computeChecksum(packet, 0, packet.length);
		packet[10] = this.checksum & 0xFF;
		packet[11] = (this.checksum >>> 8) & 0xFF;
		return packet.length;
	}
}
