'use strict';

class UDPPkt extends IHdr {
	fill() {
		this.sport = 0;
		this.dport = 0;
		this.checksum = 0;
		this.data = new ArrayBuffer(0);
	}

	static fromPacket(packet, offset, len, ipHdr) {
		const udp = new UDPPkt(false);
		const data = new Uint8Array(packet, offset, len);
		udp.sport = data[1] + (data[0] << 8);
		udp.dport = data[3] + (data[2] << 8);
		const udplen = data[5] + (data[4] << 8);
		udp.checksum = data[7] + (data[6] << 8);
		if (udplen > 0) {
			udp.data = packet.slice(offset + 8, udplen);
		} else {
			udp.data = new ArrayBuffer(0);
		}
		if (ipHdr && udp.checksum !== 0 && udp._computeChecksum(ipHdr, packet, offset) !== 0xFFFF) {
			throw new Error('Invalid UDP checksum');
		}
		return udp;
	}

	getFullLength() {
		return this.data.byteLength + 8;
	}

	_computeChecksum(ipHdr, packet, offset) {
		const fullLen = this.getFullLength();

		const pseudoIP8 = new Uint8Array(12);
		ipHdr.saddr.toBytes(pseudoIP8, 0);
		ipHdr.daddr.toBytes(pseudoIP8, 4);
		pseudoIP8[8] = 0;
		pseudoIP8[9] = 17; // UDP
		pseudoIP8[10] = (fullLen >>> 8) & 0xFF;
		pseudoIP8[11] = fullLen & 0xFF;
		let csum = computeChecksumIntermediate(pseudoIP8.buffer, 0, 12);
		csum = computeChecksum(packet, offset, fullLen, csum);
		if (csum === 0) {
			return 0xFFFF;
		}
		return csum;
	}

	toPacket(array, offset, ipHdr) {
		const packet = new Uint8Array(array, offset, this.getFullLength());
		packet[0] = (this.sport >>> 8) & 0xFF;
		packet[1] = this.sport & 0xFF;
		packet[2] = (this.dport >>> 8) & 0xFF;
		packet[3] = this.dport & 0xFF;
		const udplen = this.data.byteLength;
		packet[4] = (udplen >>> 8) & 0xFF;
		packet[5] = udplen & 0xFF;
		packet[6] = 0; // Checksum A
		packet[7] = 0; // Checksum B
		if (udplen > 0) {
			const d8 = new Uint8Array(this.data);
			for (let i = 0; i < d8.length; i++) {
				packet[8 + i] = d8[i];
			}
		}
		if (ipHdr) {
			this.checksum = this._computeChecksum(ipHdr, packet);
			packet[6] = this.checksum & 0xFF;
			packet[7] = (this.checksum >>> 8) & 0xFF;
		} else {
			this.checksum = 0;
		}
		return packet.length;
	}

	getFullLength() {
		return this.data.byteLength + 8;
	}
}
