'use strict';

const PROTO_ICMP = 1;

class ICMPPkt extends IHdr {
	fill() {
		this.type = 0;
		this.code = 0;
		this.checksum = 0;
		this.rest = 0;
		this.data = new ArrayBuffer(0);
	}

	static fromPacket(packet, offset, len) {
		const icmp = new ICMPPkt(false);
		const data = new Uint8Array(packet, offset, len);
		icmp.type = data[0];
		icmp.code = data[1];
		icmp.checksum = data[3] + (data[2] << 8);
		icmp.rest = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
		if (len > 8) {
			icmp.data = packet.slice(offset + 8);
		} else {
			icmp.data = new ArrayBuffer(0);
		}
		if (computeChecksum(packet, offset, len) !== 0) {
			throw new Error('Invalid ICMP checksum');
		}
		return icmp;
	}

	toPacket(array, offset) {
		const packet = new Uint8Array(array, offset, this.getFullLength());
		packet[0] = this.type;
		packet[1] = this.code;
		packet[2] = 0; // Checksum A
		packet[3] = 0; // Checksum B
		packet[4] = (this.rest >>> 24) & 0xFF;
		packet[5] = (this.rest >>> 16) & 0xFF;
		packet[6] = (this.rest >>> 8) & 0xFF;
		packet[7] = (this.rest) & 0xFF;
		if (this.data.byteLength > 0) {
			const d8 = new Uint8Array(this.data);
			for (let i = 0; i < d8.length; i++) {
				packet[8 + i] = d8[i];
			}
		}
		this.checksum = computeChecksum(array, offset, packet.length);
		packet[2] = this.checksum & 0xFF;
		packet[3] = (this.checksum >>> 8) & 0xFF;
		return packet.length;
	}

	getFullLength() {
		return this.data.byteLength + 8;
	}
}
