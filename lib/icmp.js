'use strict';

class ICMPHdr extends IHdr {
	fill() {
		this.type = 0;
		this.code = 0;
		this.checksum = 0;
		this.rest = 0;
		this.data = new Uint8Array(0);
	}

	static fromPacket(packet, offset, len) {
		const icmp = new ICMPHdr(false);
		const data = new Uint8Array(packet, offset, len);
		icmp.type = data[0];
		icmp.code = data[1];
		icmp.checksum = data[3] + (data[2] << 8);
		icmp.rest = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
		if (computeChecksum(packet, offset, len) !== 0) {
			throw new Error('Invalid ICMP checksum');
		}
		return icmp;
	}
}
