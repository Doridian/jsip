import { IPNet } from "./subnet.js";

let multicastNets: IPNet[] = [];

export class IPAddr {
    public static fromString(ipStr: string) {
        const ip = new IPAddr();
        const ipS = ipStr.split(".");
        ipS.forEach((str, i) => {
            ip.raw[i] = parseInt(str, 10);
        });
        return ip;
    }

    public static fromPartialByteArray(ipBytes: Uint8Array, offset = 0, len = 4) {
        const ip = new IPAddr();
        ip.raw.set(new Uint8Array(ipBytes.buffer, ipBytes.byteOffset + offset, len));
        return ip;
    }

    public static fromByteArray(ipBytes: Uint8Array, offset = 0) {
        return this.fromPartialByteArray(ipBytes, offset, 4);
    }

    public static fromBytes(a: number, b: number, c: number, d: number) {
        const ip = new IPAddr();
        ip.raw[0] = a;
        ip.raw[1] = b;
        ip.raw[2] = c;
        ip.raw[3] = d;
        return ip;
    }

    public static fromInt32(ipInt: number) {
        const ip = new IPAddr();
        ip.raw[0] = (ipInt >>> 24) & 0xFF;
        ip.raw[1] = (ipInt >>> 16) & 0xFF;
        ip.raw[2] = (ipInt >>> 8) & 0xFF;
        ip.raw[3] = ipInt & 0xFF;
        return ip;
    }

    public static setMulticastNets(nets: IPNet[]) {
        if (multicastNets.length > 0) {
            throw new Error("Multicast nets already initialized!");
        }
        multicastNets = nets.slice(0);
    }

    private raw = new Uint8Array(4);

    public equals(ip?: IPAddr) {
        if (!ip) {
            return false;
        }
        return this.raw.every((val, idx) => val === ip.raw[idx]);
    }

    public toBytes(array: Uint8Array, offset: number) {
        array.set(this.raw, offset);
    }

    public toByteArray() {
        const res = new Uint8Array(4);
        this.toBytes(res, 0);
        return res;
    }

    public toInt() {
        return this.raw[3] | (this.raw[2] << 8) | (this.raw[1] << 16) | (this.raw[0] << 24);
    }

    public toString() {
        return `${this.raw[0]}.${this.raw[1]}.${this.raw[2]}.${this.raw[3]}`;
    }

    public isMulticast() {
        return multicastNets.some((net) => net.contains(this));
    }

    public isBroadcast() {
        return this.equals(IP_BROADCAST);
    }

    public isUnicast() {
        return !this.isBroadcast() && !this.isMulticast();
    }

    public isLoopback() {
        return this.raw[0] === 127;
    }

    public isLinkLocal() {
        return this.raw[0] === 169 && this.raw[1] === 254;
    }
}

export const IP_BROADCAST = IPAddr.fromString("255.255.255.255");
export const IP_NONE = IPAddr.fromString("0.0.0.0");
export const IP_LOOPBACK = IPAddr.fromString("127.0.0.1");
