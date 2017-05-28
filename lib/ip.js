'use strict';

function computeChecksum(array, offset, len) {
	const bytes = new Uint8Array(array, offset, len);
	let csum = 0;
	for (let i = 0; i < bytes.length; i += 2) {
		csum += bytes[i] + (bytes[i + 1] << 8);
	}
	return ~csum & 0xFFFF;
}

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
		ip.b = (ipInt >> 8) & 0xFF;
		ip.c = (ipInt >> 16) & 0xFF;
		ip.d = (ipInt >> 24) & 0xFF;
		return ip;
	}

	toBytes(array, offset) {
		array[offset] = ip.a;
		array[offset + 1] = ip.b;
		array[offset + 2] = ip.c;
		array[offset + 3] = ip.d;
	}

	toString() {
		return `${this.a}.${this.b}.${this.c}.${this.d}`;
	}
}

class IPHdr {
	constructor(fill = true) {
		if (fill) {
			this.fill();
		}
	}

	fill() {
		this.version = 0;
		this.ihl = 0;
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
	}

	static fromPacket(packet) { // Uint8Array
		const ipv4 = new IPHdr(false);
		const bit = new BitArray(packet);
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
		if (computeChecksum(packet, 0, ipv4.ihl << 2) !== 0) {
			throw new Error('Invalid IPv4 checksum');
		}
		return ipv4;
	}
}