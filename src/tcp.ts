import { IHdr, computeChecksum, computeChecksumPseudo, IPacket } from "./util";
import { config } from "./config";
import { IPHdr } from "./ip";
import { BitArray } from "./bitfield";

export const PROTO_TCP = 6;

export const TCP_NS = 0x100;
export const TCP_CWR = 0x80;
export const TCP_ECE = 0x40;
export const TCP_URG = 0x20;
export const TCP_ACK = 0x10;
export const TCP_PSH = 0x08;
export const TCP_RST = 0x04;
export const TCP_SYN = 0x02;
export const TCP_FIN = 0x01;

export class TCPPkt extends IHdr implements IPacket {
	public sport = 0;
	public dport = 0;
	public checksum = 0;
	public data: Uint8Array|undefined;
	public options: Uint8Array|undefined;
	public seqno = 0;
	public ackno = 0;
	public urgptr = 0;
	public flags = 0;
	public window_size = 0;
	public mss = -1;

	fillMSS() {
		this.options = new Uint8Array(4);
		const o8 = this.options;
		o8[0] = 2;
		o8[1] = 4;
		const mss = config.mtu - 40;
		o8[2] = (mss >>> 8) & 0xFF;
		o8[3] = mss & 0xFF;
	}

	static fromPacket(packet: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) {
		const tcp = new TCPPkt(false);
		const data = new Uint8Array(packet, offset, len);
		const bit = new BitArray(packet, offset + 12);
		tcp.sport = data[1] + (data[0] << 8);
		tcp.dport = data[3] + (data[2] << 8);
		tcp.seqno = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
		tcp.ackno = data[11] + (data[10] << 8) + (data[9] << 16) + (data[8] << 24);
		const data_offset = bit.read(4) << 2;
		bit.skip(3);
		tcp.flags = bit.read(9);
		tcp.window_size = data[15] + (data[14] << 8);
		tcp.checksum = data[17] + (data[16] << 8);
		tcp.urgptr = data[19] + (data[18] << 8);
		tcp.mss = -1;

		if (data_offset > 20) {
			tcp.options = new Uint8Array(packet, 20 + offset, data_offset - 20);
			tcp.data =  new Uint8Array(packet, data_offset + offset);

			const o8 = new Uint8Array(tcp.options);
			for (let i = 0; i < o8.length; ) {
				let _len = o8[i + 1];
				if (_len <= 0) {
					break;
				}
				switch (o8[i]) {
					case 0:
						_len = o8.length;
						break;
					case 1:
						_len = 1;
						break;
					case 2:
						tcp.mss = o8[i + 3] + (o8[i + 2] << 8);
						break;
				}
				i += _len;
			}
		} else {
			tcp.options = new Uint8Array(0);
			tcp.data = new Uint8Array(packet, 20 + offset);
		}

		if (ipHdr && tcp._computeChecksum(ipHdr, data) !== 0) {
			throw new Error('Invalid TCP checksum');
		}
		return tcp;
	}

	setFlag(flag: number) {
		this.flags |= flag;
	}

	unsetFlag(flag: number) {
		this.flags &= ~flag;
	}

	hasFlag(flag: number) {
		return (this.flags & flag) === flag
	}

	getFullLength() {
		let len = 20;
		if (this.data) {
			len += this.data.byteLength;
		}
		if (this.options) {
			len += this.options.byteLength;
		}
		return len;
	}

	_computeChecksum(ipHdr: IPHdr, packet: Uint8Array) {
		let csum = computeChecksumPseudo(ipHdr, PROTO_TCP, packet.byteLength);
		return computeChecksum(packet, csum);
	}

	toPacket(array: ArrayBuffer, offset:number, ipHdr: IPHdr|undefined = undefined) {
		const packet = new Uint8Array(array, offset, this.getFullLength());
		const data_offset = (this.options ? this.options.byteLength : 0) + 20;
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
		packet[12] = ((data_offset >>> 2) << 4) | ((this.flags >>> 8) & 0x0F);
		packet[13] = this.flags & 0xFF;
		packet[14] = (this.window_size >>> 8) & 0xFF;
		packet[15] = this.window_size & 0xFF;
		packet[16] = 0; // Checksum A
		packet[17] = 0; // Checksum B
		packet[18] = (this.urgptr >>> 8) & 0xFF;
		packet[19] = this.urgptr & 0xFF;
		if (this.options && this.options.byteLength > 0) {
			const o8 = new Uint8Array(this.options);
			for (let i = 0; i < o8.length; i++) {
				packet[20 + i] = o8[i];
			}
		}
		if (this.data && this.data.byteLength > 0) {
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
		return packet.byteLength;
	}
}
