import { computeChecksum } from "../../util/checksum.js";
import { logDebug } from "../../util/log.js";
import { IPAddr } from "./address.js";

export const enum IPPROTO {
  NONE = 0,
  ICMP = 1,
  TCP = 6,
  UDP = 17,
}

export class IPHdr {
  public static fromPacket(packet: ArrayBuffer, offset: number) {
    const ipv4 = new IPHdr();
    const data = new Uint8Array(packet, offset);

    // [0]
    ipv4.version = data[0]! >>> 4;
    if (ipv4.version !== 4) {
      logDebug(`Ignoring IP version: ${ipv4.version}`);
      return undefined;
    }

    ipv4.ihl = data[0]! & 0b1111;
    const ipHdrLen = ipv4.ihl << 2;

    // [1]
    const flag1Data = data[1]!;
    ipv4.dscp = flag1Data >>> 2;
    ipv4.ecn = flag1Data & 0b11;

    // [2]
    ipv4.len = data[3]! | (data[2]! << 8);
    ipv4.id = data[5]! | (data[4]! << 8);

    // [6]
    const flags = data[6]! >>> 5;
    ipv4.df = (flags & 0x2) === 0x2;
    ipv4.mf = (flags & 0x1) === 0x1;

    ipv4.fragOffset = ((data[6]! & 0b1_1111) << 8) | data[7]!;

    // [8]
    ipv4.ttl = data[8]!;
    ipv4.protocol = data[9]!;
    ipv4.checksum = data[11]! | (data[10]! << 8);
    ipv4.saddr = IPAddr.fromByteArray(data, 12);
    ipv4.daddr = IPAddr.fromByteArray(data, 16);

    ipv4.options =
      ipHdrLen > 20
        ? new Uint8Array(packet, offset + 20, ipHdrLen - 20)
        : new Uint8Array(0);

    if (ipv4.checksum !== 0) {
      const checksum = computeChecksum(
        new Uint8Array(packet, offset, ipHdrLen),
      );
      if (checksum !== 0) {
        logDebug(`Invalid IPv4 checksum: ${checksum} !== 0`);
        return undefined;
      }
    }

    return ipv4;
  }

  public ihl = 5;
  public dscp = 0;
  public ecn = 0;
  public len = 0;
  public id = 0;
  public df = false;
  public mf = false;
  public fragOffset = 0;
  public protocol = IPPROTO.NONE;
  public saddr?: IPAddr;
  public daddr?: IPAddr;
  public options?: Uint8Array;
  private version = 4;
  private ttl = 64;
  private checksum = 0;

  public setContentLength(len: number) {
    this.len = this.getContentOffset() + len;
  }

  public getContentLength() {
    return this.len - this.getContentOffset();
  }

  public getFullLength() {
    return this.len;
  }

  public getContentOffset() {
    return this.ihl << 2;
  }

  public makeReply() {
    const replyIp = new IPHdr();
    replyIp.protocol = this.protocol;

    replyIp.saddr = this.daddr!.isUnicast() ? this.daddr : undefined;
    replyIp.daddr = this.saddr!;

    return replyIp;
  }

  public toPacket(array: ArrayBuffer, offset: number) {
    const packet = new Uint8Array(
      array,
      offset,
      (this.options ? this.options.byteLength : 0) + 20,
    );
    this.ihl = packet.length >>> 2;
    packet[0] = ((this.version & 0xf) << 4) | (this.ihl & 0xf);
    packet[1] = ((this.dscp & 0xfc) << 2) | (this.ecn & 0x3);
    packet[2] = (this.len >>> 8) & 0xff;
    packet[3] = this.len & 0xff;
    packet[4] = (this.id >>> 8) & 0xff;
    packet[5] = this.id & 0xff;
    const flags = (this.df ? 0x2 : 0x0) | (this.mf ? 0x1 : 0x0);
    packet[6] = (flags << 5) | ((this.fragOffset >>> 8) & 0x1f);
    packet[7] = this.fragOffset & 0xff;
    packet[8] = this.ttl & 0xff;
    packet[9] = this.protocol & 0xff;
    packet[10] = 0; // Checksum A
    packet[11] = 0; // Checksum B
    this.saddr!.toBytes(packet, 12);
    this.daddr!.toBytes(packet, 16);
    if (this.options && this.options.byteLength > 0) {
      const o8 = new Uint8Array(this.options);
      for (const [i, element] of o8.entries()) {
        packet[i + 12] = element!;
      }
    }
    this.checksum = computeChecksum(packet);
    packet[10] = this.checksum & 0xff;
    packet[11] = (this.checksum >>> 8) & 0xff;
    return packet.length;
  }
}
