import { stringToBuffer } from "../../../../util/string.js";
import { IPAddr } from "../../address.js";
import { DNSResult, makeDNSLabel } from "./util.js";
import { DNS_CLASS, DNS_TYPE } from "./index.js";

export class DNSAnswer {
  public name = "";
  public type = DNS_TYPE.A;
  public class = DNS_CLASS.IN;
  public ttl = 0;
  private data?: DNSResult;
  private dataRaw?: Uint8Array;

  public getTTL() {
    return this.ttl >>> 0;
  }

  public setData(data: DNSResult) {
    this.data = data;
    if (data instanceof IPAddr) {
      this.dataRaw = data.toByteArray();
    } else if (typeof data === "string") {
      this.dataRaw = new Uint8Array(stringToBuffer(data));
    } else {
      this.dataRaw = undefined;
    }
  }

  public getData() {
    return this.data;
  }

  public getDataRaw() {
    return this.dataRaw;
  }

  public getDataLen() {
    return this.dataRaw ? this.dataRaw.byteLength : 0;
  }

  public write(packet: Uint8Array, pos: number) {
    const nameLbL = makeDNSLabel(this.name);
    for (let i = 0; i < nameLbL.byteLength; i++) {
      packet[pos + i] = nameLbL[i]!;
    }
    pos += nameLbL.byteLength;

    packet[pos++] = (this.type >>> 8) & 0xff;
    packet[pos++] = this.type & 0xff;
    packet[pos++] = (this.class >>> 8) & 0xff;
    packet[pos++] = this.class & 0xff;

    packet[pos++] = (this.ttl >>> 24) & 0xff;
    packet[pos++] = (this.ttl >>> 16) & 0xff;
    packet[pos++] = (this.ttl >>> 8) & 0xff;
    packet[pos++] = this.ttl & 0xff;

    if (this.dataRaw) {
      for (let i = 0; i < this.dataRaw.byteLength; i++) {
        packet[pos + i] = this.dataRaw[i]!;
      }
      pos += this.dataRaw.byteLength;
    }

    return pos;
  }
}
