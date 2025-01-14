import { makeDNSLabel } from "./util.js";
import { DNS_CLASS, DNS_TYPE } from "./index.js";

export class DNSQuestion {
  public name = "";
  public type = DNS_TYPE.A;
  public class = DNS_CLASS.IN;

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

    return pos;
  }
}
