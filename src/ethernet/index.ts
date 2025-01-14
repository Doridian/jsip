import { MACAddr } from "./address.js";

export const enum ETH_TYPE {
  NONE = 0x00_00,
  IP = 0x08_00,
  IP6 = 0x86_dd,
  ARP = 0x08_06,
}

export const ETH_LEN = 14;

export class EthHdr {
  public static fromPacket(packet: ArrayBuffer, offset: number) {
    const eth = new EthHdr();
    const data = new Uint8Array(packet, offset);
    eth.daddr = MACAddr.fromByteArray(data, 0);
    eth.saddr = MACAddr.fromByteArray(data, 6);
    eth.ethtype = data[13]! | (data[12]! << 8);
    return eth;
  }

  public ethtype = ETH_TYPE.NONE;
  public saddr?: MACAddr;
  public daddr?: MACAddr;

  public makeReply() {
    const replyEth = new EthHdr();
    replyEth.ethtype = this.ethtype;
    replyEth.saddr = this.daddr;
    replyEth.daddr = this.saddr;
    return replyEth;
  }

  public getContentOffset() {
    return ETH_LEN;
  }

  public toPacket(array: ArrayBuffer, offset: number) {
    const packet = new Uint8Array(array, offset, ETH_LEN);
    this.daddr!.toBytes(packet, 0);
    this.saddr!.toBytes(packet, 6);
    packet[12] = (this.ethtype >>> 8) & 0xff;
    packet[13] = this.ethtype & 0xff;
    return ETH_LEN;
  }
}
