import { computeChecksumPseudo, computeChecksum, IPacket } from "./util";
import { IPHdr } from "./ip";

export const PROTO_UDP = 17;

export class UDPPkt implements IPacket {
	public sport = 0;
	public dport = 0;
	private checksum = 0;
	public data: Uint8Array|undefined = undefined;

	static fromPacket(packet: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) {
		const udp = new UDPPkt();
		const data = new Uint8Array(packet, offset, len);
		udp.sport = data[1] + (data[0] << 8);
		udp.dport = data[3] + (data[2] << 8);
		const udplen = (data[5] + (data[4] << 8)) - 8;
		udp.checksum = data[7] + (data[6] << 8);
		if (udplen > 0) {
			const udBeg = offset + 8;
			udp.data = new Uint8Array(packet, udBeg, udplen);
		} else {
			udp.data = undefined;
		}

		if (ipHdr && udp.checksum !== 0) {
			const checksum = udp._computeChecksum(ipHdr, new Uint8Array(packet, offset, udp.getFullLength()));
			if (checksum !== 0xFFFF && (checksum !== 0 || udp.checksum !== 0xFFFF)) {
				throw new Error(`Invalid UDP checksum: ${checksum} != 65535`);
			}
		}
		return udp;
	}

	getFullLength() {
		if (!this.data) {
			return 8;
		}
		return this.data.byteLength + 8;
	}

	_computeChecksum(ipHdr: IPHdr, packet: Uint8Array) {
		let csum = computeChecksumPseudo(ipHdr, PROTO_UDP, packet.byteLength);
		csum = computeChecksum(packet, csum);
		if (csum === 0) {
			return 0xFFFF;
		}
		return csum;
	}

	toPacket(array: ArrayBuffer, offset: number, ipHdr: IPHdr|undefined = undefined) {
		const packet = new Uint8Array(array, offset, this.getFullLength());
		packet[0] = (this.sport >>> 8) & 0xFF;
		packet[1] = this.sport & 0xFF;
		packet[2] = (this.dport >>> 8) & 0xFF;
		packet[3] = this.dport & 0xFF;
		const udplen = (this.data ? this.data.byteLength : 0) + 8;
		packet[4] = (udplen >>> 8) & 0xFF;
		packet[5] = udplen & 0xFF;
		packet[6] = 0; // Checksum A
		packet[7] = 0; // Checksum B
		if (this.data && udplen > 8) {
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
}
