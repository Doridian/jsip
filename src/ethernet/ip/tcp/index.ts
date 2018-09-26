import { config } from "../../../config";
import { IPacket } from "../../../ipacket";
import { BitArray } from "../../../util/bitfield";
import { computeChecksum, computeChecksumPseudo } from "../../../util/checksum";
import { IPHdr, IPPROTO } from "../index";

export const enum TCP_FLAGS {
    NS = 0x100,
    CWR = 0x80,
    ECE = 0x40,
    URG = 0x20,
    ACK = 0x10,
    PSH = 0x08,
    RST = 0x04,
    SYN = 0x02,
    FIN = 0x01,
}

export class TCPPkt implements IPacket {
    public static fromPacket(packet: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) {
        const tcp = new TCPPkt();
        const data = new Uint8Array(packet, offset, len);
        const bit = new BitArray(packet, offset + 12);
        tcp.sport = data[1] + (data[0] << 8);
        tcp.dport = data[3] + (data[2] << 8);
        tcp.seqno = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
        tcp.ackno = data[11] + (data[10] << 8) + (data[9] << 16) + (data[8] << 24);
        const dataOffset = bit.read(4) << 2;
        bit.skip(3);
        tcp.flags = bit.read(9);
        tcp.windowSize = data[15] + (data[14] << 8);
        tcp.checksum = data[17] + (data[16] << 8);
        tcp.urgptr = data[19] + (data[18] << 8);
        tcp.mss = -1;

        if (dataOffset > 20) {
            tcp.options = new Uint8Array(packet, 20 + offset, dataOffset - 20);
            tcp.data =  new Uint8Array(packet, dataOffset + offset);

            const o8 = new Uint8Array(tcp.options);
            for (let i = 0; i < o8.length;) {
                let optLen = o8[i + 1];
                if (optLen <= 0) {
                    break;
                }
                switch (o8[i]) {
                    case 0:
                        optLen = o8.length;
                        break;
                    case 1:
                        optLen = 1;
                        break;
                    case 2:
                        tcp.mss = o8[i + 3] + (o8[i + 2] << 8);
                        break;
                }
                i += optLen;
            }
        } else {
            tcp.options = new Uint8Array(0);
            tcp.data = new Uint8Array(packet, 20 + offset);
        }

        if (ipHdr && tcp._computeChecksum(ipHdr, data) !== 0) {
            throw new Error("Invalid TCP checksum");
        }
        return tcp;
    }

    public sport = 0;
    public dport = 0;
    public checksum = 0;
    public data?: Uint8Array;
    public options?: Uint8Array;
    public seqno = 0;
    public ackno = 0;
    public urgptr = 0;
    public flags = 0;
    public windowSize = 0;
    public mss = -1;

    public fillMSS() {
        this.options = new Uint8Array(4);
        const o8 = this.options;
        o8[0] = 2;
        o8[1] = 4;
        const mss = config.mtu - 40;
        o8[2] = (mss >>> 8) & 0xFF;
        o8[3] = mss & 0xFF;
    }

    public setFlag(flag: TCP_FLAGS) {
        this.flags |= flag;
    }

    public unsetFlag(flag: TCP_FLAGS) {
        this.flags &= ~flag;
    }

    public hasFlag(flag: TCP_FLAGS) {
        return (this.flags & flag) === flag;
    }

    public getFullLength() {
        let len = 20;
        if (this.data) {
            len += this.data.byteLength;
        }
        if (this.options) {
            len += this.options.byteLength;
        }
        return len;
    }

    public _computeChecksum(ipHdr: IPHdr, packet: Uint8Array) {
        const csum = computeChecksumPseudo(ipHdr, IPPROTO.TCP, packet.byteLength);
        return computeChecksum(packet, csum);
    }

    public toPacket(array: ArrayBuffer, offset: number, ipHdr?: IPHdr) {
        const packet = new Uint8Array(array, offset, this.getFullLength());
        const dataOffset = (this.options ? this.options.byteLength : 0) + 20;
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
        packet[12] = ((dataOffset >>> 2) << 4) | ((this.flags >>> 8) & 0x0F);
        packet[13] = this.flags & 0xFF;
        packet[14] = (this.windowSize >>> 8) & 0xFF;
        packet[15] = this.windowSize & 0xFF;
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
                packet[dataOffset + i] = d8[i];
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
