import { IInterface } from "../../interface/index.js";
import { MACAddr } from "../address.js";
import { IPAddr } from "../ip/address.js";

export const ARP_HTYPE = 1;
export const ARP_PTYPE = 0x8_00;
export const ARP_HLEN = 6;
export const ARP_PLEN = 4;

export const ARP_REQUEST = 1;
export const ARP_REPLY = 2;

export const ARP_LEN = 2 * ARP_HLEN + 2 * ARP_PLEN + 8;

export class ARPPkt {
  public static fromPacket(packet: ArrayBuffer, offset: number) {
    const arp = new ARPPkt();
    const data = new Uint8Array(packet, offset);
    arp.htype = data[1]! | (data[0]! << 8);
    arp.ptype = data[3]! | (data[2]! << 8);
    arp.hlen = data[4]!;
    arp.plen = data[5]!;
    arp.operation = data[7]! | (data[6]! << 8);
    arp.sha = MACAddr.fromByteArray(data, 8);
    arp.spa = IPAddr.fromByteArray(data, 14);
    arp.tha = MACAddr.fromByteArray(data, 18);
    arp.tpa = IPAddr.fromByteArray(data, 24);
    return arp;
  }

  public htype = ARP_HTYPE;
  public ptype = ARP_PTYPE;
  public hlen = ARP_HLEN;
  public plen = ARP_PLEN;
  public operation = 0;
  public sha?: MACAddr;
  public spa?: IPAddr;
  public tha?: MACAddr;
  public tpa?: IPAddr;

  public makeReply(iface: IInterface) {
    if (this.operation !== ARP_REQUEST) {
      return undefined;
    }
    const replyARP = new ARPPkt();
    replyARP.htype = this.htype;
    replyARP.ptype = this.ptype;
    replyARP.hlen = this.hlen;
    replyARP.plen = this.plen;
    replyARP.operation = ARP_REPLY;
    replyARP.sha = iface.getMAC();
    replyARP.spa = this.tpa;
    replyARP.tha = this.sha;
    replyARP.tpa = this.spa;
    return replyARP;
  }

  public toPacket(array: ArrayBuffer, offset: number) {
    const packet = new Uint8Array(array, offset, ARP_LEN);

    packet[0] = (this.htype >>> 8) & 0xff;
    packet[1] = this.htype & 0xff;
    packet[2] = (this.ptype >>> 8) & 0xff;
    packet[3] = this.ptype & 0xff;
    packet[4] = this.hlen;
    packet[5] = this.plen;
    packet[6] = (this.operation >>> 8) & 0xff;
    packet[7] = this.operation & 0xff;

    this.sha!.toBytes(packet, 8);
    this.spa!.toBytes(packet, 14);
    this.tha!.toBytes(packet, 18);
    this.tpa!.toBytes(packet, 24);

    return ARP_LEN;
  }
}
