import { DNS_CLASS, DNS_TYPE } from "./index";
import { makeDNSLabel } from "./util";

export class DNSAnswer {
    public name: string = "";
    public type = DNS_TYPE.A;
    public class = DNS_CLASS.IN;
    public ttl = 0;
    public data?: Uint8Array;
    public datapos = 0;

    public getTTL() {
        return this.ttl >>> 0;
    }

    public write(packet: Uint8Array, pos: number) {
        const nameLbL = makeDNSLabel(this.name);
        for (let i = 0; i < nameLbL.byteLength; i++) {
            packet[pos + i] = nameLbL[i];
        }
        pos += nameLbL.byteLength;

        packet[pos++] = (this.type >>> 8) & 0xFF;
        packet[pos++] = this.type & 0xFF;
        packet[pos++] = (this.class >>> 8) & 0xFF;
        packet[pos++] = this.class & 0xFF;

        packet[pos++] = (this.ttl >>> 24) & 0xFF;
        packet[pos++] = (this.ttl >>> 16) & 0xFF;
        packet[pos++] = (this.ttl >>> 8) & 0xFF;
        packet[pos++] = this.ttl & 0xFF;

        if (this.data) {
            for (let i = 0; i  < this.data.byteLength; i++) {
                packet[pos + i] = this.data[i];
            }
            pos += this.data.byteLength;
        }

        return pos;
    }
}
