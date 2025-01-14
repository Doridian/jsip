import { IPacket } from "../../../ipacket.js";
import {
  computeChecksum,
  computeChecksumPseudo,
} from "../../../util/checksum.js";
import { IPHdr, IPPROTO } from "../index.js";

export const enum TCP_FLAGS {
  NS = 0x1_00,
  CWR = 0x80,
  ECE = 0x40,
  URG = 0x20,
  ACK = 0x10,
  PSH = 0x08,
  RST = 0x04,
  SYN = 0x02,
  FIN = 0x01,
}

export const enum TCP_OPTIONS {
  MSS = 0x02,
  SACK_SUPPORT = 0x04,
  SACK = 0x05,
}

export class TCPPkt implements IPacket {
  public static fromPacket(
    packet: ArrayBuffer,
    offset: number,
    len: number,
    ipHdr: IPHdr,
  ) {
    const tcp = new TCPPkt();
    const data = new Uint8Array(packet, offset, len);
    tcp.sport = data[1]! + (data[0]! << 8);
    tcp.dport = data[3]! + (data[2]! << 8);
    tcp.seqno =
      (data[7]! + (data[6]! << 8)) | (data[5]! << 16) | (data[4]! << 24);
    tcp.ackno =
      (data[11]! + (data[10]! << 8)) | (data[9]! << 16) | (data[8]! << 24);
    const dataOffset = (data[12]! & 0b1111_0000) >>> 2;
    tcp.flags = data[13]! || (data[12]! & 0b0000_0001) << 8;
    tcp.windowSize = data[15]! | (data[14]! << 8);
    tcp.checksum = data[17]! | (data[16]! << 8);
    tcp.urgptr = data[19]! | (data[18]! << 8);
    tcp.mss = -1;

    if (dataOffset > 20) {
      tcp.options = new Uint8Array(packet, 20 + offset, dataOffset - 20);
      tcp.data = new Uint8Array(packet, dataOffset + offset);

      const o8 = new Uint8Array(tcp.options);
      for (let i = 0; i < o8.length; ) {
        let optLen = o8[i + 1]!;
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
            tcp.mss = o8[i + 3]! | (o8[i + 2]! << 8);
            break;
        }
        i += optLen;
      }
    } else {
      tcp.options = undefined;
      tcp.data = new Uint8Array(packet, 20 + offset);
    }

    const checksum = tcp.computeChecksum(ipHdr, data);
    if (checksum !== 0) {
      throw new Error(`Invalid TCP checksum: ${checksum} != 0`);
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

  public getProto() {
    return IPPROTO.TCP;
  }

  public setOption(typ: number, data: Uint8Array) {
    const len = data.byteLength + 2;

    let base = this.options;
    if (!base) {
      base = new Uint8Array();
    }

    this.options = new Uint8Array(base.byteLength + len);
    this.options.set(base, 0);
    this.options[base.byteLength] = typ;
    this.options[base.byteLength + 1] = len;
    this.options.set(data, base.byteLength + 2);
  }

  public decodeOptions() {
    if (!this.options) {
      return new Map<number, Uint8Array>();
    }

    const options = new Map<number, Uint8Array>();

    let i = 0;
    while (i < this.options.byteLength) {
      const typ = this.options[i]!;
      if (typ == 0x01 || typ == 0x00) {
        i++;
        continue;
      }

      const len = this.options[i + 1]!;
      if (len < 1) {
        break;
      }

      options.set(typ, this.options.slice(i + 2, i + len));
      i += len;
    }

    return options;
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

  private getDataOffset() {
    let dataOffset = (this.options ? this.options.byteLength : 0) + 20;
    dataOffset += dataOffset % 4;
    return dataOffset;
  }

  public getFullLength() {
    let len = this.getDataOffset();
    if (this.data) {
      len += this.data.byteLength;
    }
    return len;
  }

  public toPacket(array: ArrayBuffer, offset: number, ipHdr?: IPHdr) {
    const packet = new Uint8Array(array, offset, this.getFullLength());
    const dataOffset = this.getDataOffset();

    packet[0] = (this.sport >>> 8) & 0xff;
    packet[1] = this.sport & 0xff;
    packet[2] = (this.dport >>> 8) & 0xff;
    packet[3] = this.dport & 0xff;
    packet[4] = (this.seqno >>> 24) & 0xff;
    packet[5] = (this.seqno >>> 16) & 0xff;
    packet[6] = (this.seqno >>> 8) & 0xff;
    packet[7] = this.seqno & 0xff;
    packet[8] = (this.ackno >>> 24) & 0xff;
    packet[9] = (this.ackno >>> 16) & 0xff;
    packet[10] = (this.ackno >>> 8) & 0xff;
    packet[11] = this.ackno & 0xff;
    packet[12] = ((dataOffset << 2) & 0xf0) | ((this.flags >>> 8) & 0x0f);
    packet[13] = this.flags & 0xff;
    packet[14] = (this.windowSize >>> 8) & 0xff;
    packet[15] = this.windowSize & 0xff;
    packet[16] = 0; // Checksum A
    packet[17] = 0; // Checksum B
    packet[18] = (this.urgptr >>> 8) & 0xff;
    packet[19] = this.urgptr & 0xff;

    if (dataOffset > 20) {
      const o8 = new Uint8Array(this.options!);
      for (let i = 0; i < o8.byteLength; i++) {
        packet[20 + i] = o8[i]!;
      }
      for (let i = o8.byteLength + 20; i < dataOffset; i++) {
        packet[i] = 0x00;
      }
    }
    if (this.data && this.data.byteLength > 0) {
      const d8 = new Uint8Array(this.data);
      for (let i = 0; i < d8.byteLength; i++) {
        packet[dataOffset + i] = d8[i]!;
      }
    }
    if (ipHdr) {
      this.checksum = this.computeChecksum(ipHdr, packet);
      packet[16] = this.checksum & 0xff;
      packet[17] = (this.checksum >>> 8) & 0xff;
    } else {
      this.checksum = 0;
    }
    return packet.byteLength;
  }

  private computeChecksum(ipHdr: IPHdr, packet: Uint8Array) {
    const csum = computeChecksumPseudo(ipHdr, IPPROTO.TCP, packet.byteLength);
    return computeChecksum(packet, csum);
  }
}
