import { IPacket } from "../../../ipacket.js";
import {
  computeChecksum,
  computeChecksumPseudo,
} from "../../../util/checksum.js";
import { IPHdr, IPPROTO } from "../index.js";

export class UDPPkt implements IPacket {
  public static fromPacket(
    packet: ArrayBuffer,
    offset: number,
    len: number,
    ipHdr: IPHdr,
  ) {
    const udp = new UDPPkt();
    const data = new Uint8Array(packet, offset, len);

    udp.sport = data[1]! | (data[0]! << 8);
    udp.dport = data[3]! | (data[2]! << 8);
    const udplen = (data[5]! | (data[4]! << 8)) - 8;
    udp.checksum = data[7]! | (data[6]! << 8);
    if (udplen > 0) {
      const udBeg = offset + 8;
      udp.data = new Uint8Array(packet, udBeg, udplen);
    } else {
      udp.data = undefined;
    }

    if (ipHdr && udp.checksum !== 0) {
      const checksum = udp.computeChecksum(
        ipHdr,
        new Uint8Array(packet, offset, udp.getFullLength()),
      );
      if (
        checksum !== 0xff_ff &&
        (checksum !== 0 || udp.checksum !== 0xff_ff)
      ) {
        throw new Error(`Invalid UDP checksum: ${checksum} != 65535`);
      }
    }
    return udp;
  }

  public sport = 0;
  public dport = 0;
  public data?: Uint8Array;
  private checksum = 0;

  public getProto() {
    return IPPROTO.UDP;
  }

  public getFullLength() {
    if (!this.data) {
      return 8;
    }
    return this.data.byteLength + 8;
  }

  public toPacket(array: ArrayBuffer, offset: number, ipHdr?: IPHdr) {
    const packet = new Uint8Array(array, offset, this.getFullLength());
    packet[0] = (this.sport >>> 8) & 0xff;
    packet[1] = this.sport & 0xff;
    packet[2] = (this.dport >>> 8) & 0xff;
    packet[3] = this.dport & 0xff;
    const udplen = (this.data ? this.data.byteLength : 0) + 8;
    packet[4] = (udplen >>> 8) & 0xff;
    packet[5] = udplen & 0xff;
    packet[6] = 0; // Checksum A
    packet[7] = 0; // Checksum B
    if (this.data && udplen > 8) {
      const d8 = new Uint8Array(this.data);
      for (const [i, element] of d8.entries()) {
        packet[8 + i] = element!;
      }
    }
    if (ipHdr) {
      this.checksum = this.computeChecksum(ipHdr, packet);
      packet[6] = this.checksum & 0xff;
      packet[7] = (this.checksum >>> 8) & 0xff;
    } else {
      this.checksum = 0;
    }
    return packet.length;
  }

  private computeChecksum(ipHdr: IPHdr, packet: Uint8Array) {
    let csum = computeChecksumPseudo(ipHdr, IPPROTO.UDP, packet.byteLength);
    csum = computeChecksum(packet, csum);
    if (csum === 0) {
      return 0xff_ff;
    }
    return csum;
  }
}
