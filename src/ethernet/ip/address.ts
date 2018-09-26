import { IPNETS_MULTICAST } from "./subnet";

export class IPAddr {
    public static fromString(ipStr: string) {
        const ip = new IPAddr();
        const ipS = ipStr.split(".");
        ip.a = parseInt(ipS[0], 10);
        ip.b = parseInt(ipS[1], 10);
        ip.c = parseInt(ipS[2], 10);
        ip.d = parseInt(ipS[3], 10);
        return ip;
    }

    public static fromByteArray(ipBytes: Uint8Array, offset = 0) {
        const ip = new IPAddr();
        ip.a = ipBytes[offset];
        ip.b = ipBytes[offset + 1];
        ip.c = ipBytes[offset + 2];
        ip.d = ipBytes[offset + 3];
        return ip;
    }

    public static fromBytes(a: number, b: number, c: number, d: number) {
        const ip = new IPAddr();
        ip.a = a;
        ip.b = b;
        ip.c = c;
        ip.d = d;
        return ip;
    }

    public static fromInt32(ipInt: number) {
        const ip = new IPAddr();
        ip.d = ipInt & 0xFF;
        ip.c = (ipInt >>> 8) & 0xFF;
        ip.b = (ipInt >>> 16) & 0xFF;
        ip.a = (ipInt >>> 24) & 0xFF;
        return ip;
    }

    private a = 0;
    private b = 0;
    private c = 0;
    private d = 0;

    public equals(ip?: IPAddr) {
        if (!ip) {
            return false;
        }
        return ip.a === this.a && ip.b === this.b && ip.c === this.c && ip.d === this.d;
    }

    public toBytes(array: Uint8Array, offset: number) {
        array[offset] = this.a;
        array[offset + 1] = this.b;
        array[offset + 2] = this.c;
        array[offset + 3] = this.d;
    }

    public toByteArray() {
        const res = new Uint8Array(4);
        this.toBytes(res, 0);
        return res;
    }

    public toInt() {
        return this.d + (this.c << 8) + (this.b << 16) + (this.a << 24);
    }

    public toString() {
        return `${this.a}.${this.b}.${this.c}.${this.d}`;
    }

    public isMulticast() {
        return IPNETS_MULTICAST.some((net) => net.contains(this));
    }

    public isBroadcast() {
        return this.equals(IP_BROADCAST);
    }

    public isUnicast() {
        return !this.isBroadcast() && !this.isMulticast();
    }
}

export const IP_BROADCAST = IPAddr.fromString("255.255.255.255");
export const IP_NONE = IPAddr.fromString("0.0.0.0");
