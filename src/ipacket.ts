import { IPHdr, IPPROTO } from "./ethernet/ip/index.js";

export interface IPacket {
  toPacket(array: ArrayBuffer, offset: number, ipHdr?: IPHdr): number;
  getFullLength(): number;
  getProto(): IPPROTO;
}
