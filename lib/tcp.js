'use strict';

const PROTO_TCP = 6;

const TCP_NS = 0x100;
const TCP_CWR = 0x80;
const TCP_ECE = 0x40;
const TCP_URG = 0x20;
const TCP_ACK = 0x10;
const TCP_PSH = 0x08;
const TCP_RST = 0x04;
const TCP_SYN = 0x02;
const TCP_FIN = 0x01;

class TCPPkt extends IHdr {
	fill() {
		this.sport = 0;
		this.dport = 0;
		this.checksum = 0;
		this.data = new ArrayBuffer(0);
		this.options = new ArrayBuffer(0);
		this.seqno = 0;
		this.ackno = 0;
		this.urgptr = 0;
		this.flags = 0;
		this.window_size = 0;
	}

	static fromPacket(packet, offset, len, ipHdr) {
		const tcp = new TCPPkt(false);
		const data = new Uint8Array(packet, offset, len);
		const bit = new BitArray(packet, offset + 12);
		tcp.sport = data[1] + (data[0] << 8);
		tcp.dport = data[3] + (data[2] << 8);
		tcp.seqno = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
		tcp.ackno = data[11] + (data[10] << 8) + (data[9] << 16) + (data[8] << 24);
		const data_offset = (bit.read(4) << 2) - 20;
		bit.skip(3);
		tcp.flags = bit.read(9);
		tcp.window_size = data[15] + (data[14] << 8);
		tcp.checksum = data[17] + (data[16] << 8);
		tcp.urgptr = data[19] + (data[18] << 8);

		if (data_offset > 0) {
			tcp.options = packet.slice(20, data_offset);
			tcp.data = packet.slice(data_offset);
		} else {
			tcp.options = new ArrayBuffer(0);
			tcp.data = packet.slice(20);
		}
		if (ipHdr && tcp._computeChecksum(ipHdr, packet, offset) !== 0) {
			throw new Error('Invalid TCP checksum');
		}
		return tcp;
	}

	setFlag(flag) {
		this.flags |= flag;
	}

	unsetFlag(flag) {
		this.flags &= ~flag;
	}

	hasFlag(flag) {
		return (this.flags & flag) === flag
	}

	getFullLength() {
		return this.data.byteLength + this.options.byteLength + 20;
	}

	_computeChecksum(ipHdr, packet, offset) {
		const fullLen = this.getFullLength();
		let csum = computeChecksumPseudo(ipHdr, PROTO_TCP, fullLen);
		return computeChecksum(packet, offset, fullLen, csum);
	}

	toPacket(array, offset, ipHdr) {
		const packet = new Uint8Array(array, offset, this.getFullLength());
		const data_offset = this.options.byteLength + 20;
		packet[0] = (this.sport >>> 8) & 0xFF;
		packet[1] = this.sport & 0xFF;
		packet[2] = (this.dport >>> 8) & 0xFF;
		packet[3] = this.dport & 0xFF;
		packet[4] = (this.seqno >>> 24) & 0xFF;
		packet[5] = (this.seqno >>> 16) & 0xFF;
		packet[6] = (this.seqno >>> 8) & 0xFF;
		packet[7] = this.seqno & 0xFF;
		packet[8] = (this.ackno >>> 24) & 0xFF;
		packet[9] = (this.ackno >>> 16) & 0xFF;
		packet[10] = (this.ackno >>> 8) & 0xFF;
		packet[11] = this.ackno & 0xFF;
		packet[12] = ((data_offset >>> 2) << 4) + ((this.flags >>> 8) & 0x0F);
		packet[13] = this.flags & 0xFF;
		packet[14] = (this.window_size >>> 8) & 0xFF;
		packet[15] = this.window_size & 0xFF;
		packet[16] = 0; // Checksum A
		packet[17] = 0; // Checksum B
		packet[18] = (this.urgptr >>> 8) & 0xFF;
		packet[19] = this.urgptr & 0xFF;
		if (this.options.byteLength > 0) {
			const o8 = new Uint8Array(this.options);
			for (let i = 0; i < o8.length; i++) {
				packet[20 + i] = o8[i];
			}
		}
		if (this.data.byteLength > 0) {
			const d8 = new Uint8Array(this.data);
			for (let i = 0; i < d8.length; i++) {
				packet[data_offset + i] = d8[i];
			}
		}
		if (ipHdr) {
			this.checksum = this._computeChecksum(ipHdr, packet);
			packet[16] = this.checksum & 0xFF;
			packet[17] = (this.checksum >>> 8) & 0xFF;
		} else {
			this.checksum = 0;
		}
		return packet.length;
	}
}
