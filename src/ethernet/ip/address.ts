import { IPNet } from "./subnet.js";

let multicastNets: IPNet[] = [];

export class IPAddr {
    public static fromString(ipStr: string) {
        const ip = new IPAddr();
        const ipS = ipStr.split(".");
        for (let i = 0; i < 4; i++) {
            ip.raw[3 - i] = parseInt(ipS[i], 10);
        }
        return ip;
    }

    public static fromByteArray(ipBytes: ArrayLike<number>, offset = 0, len = 4) {
        const ip = new IPAddr();
        for (let i = 0; i < len; i++) {
            ip.raw[3 - i] = ipBytes[offset + i];
        }
        return ip;
    }

    public static fromInt32(ipInt: number) {
        const ip = new IPAddr();
        ip.raw32[0] = ipInt;
        return ip;
    }

    public static setMulticastNets(nets: IPNet[]) {
        if (multicastNets.length > 0) {
            throw new Error("Multicast nets already initialized!");
        }
        multicastNets = nets.slice(0);
    }

    private raw: Uint8Array;
    private raw32: Uint32Array;

    constructor() {
        const buffer = new ArrayBuffer(4);
        this.raw = new Uint8Array(buffer);
        this.raw32 = new Uint32Array(buffer);
    }

    public equals(ip?: IPAddr) {
        if (!ip) {
            return false;
        }
        return this.raw32[0] === ip.raw32[0];
    }

    public toBytes(array: Uint8Array, offset: number) {
        for (let i = 0; i < 4; i++) {
            array[i + offset] = this.raw[3 - i];
        }
    }

    public toByteArray() {
        const res = new Uint8Array(4);
        this.toBytes(res, 0);
        return res;
    }

    public toInt() {
        return this.raw32[0];
    }

    public toString() {
        return `${this.raw[3]}.${this.raw[2]}.${this.raw[1]}.${this.raw[0]}`;
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
        return this.raw[3] === 127;
    }

    public isLinkLocal() {
        return this.raw[3] === 169 && this.raw[2] === 254;
    }
}

export const IP_BROADCAST = IPAddr.fromString("255.255.255.255");
export const IP_NONE = IPAddr.fromString("0.0.0.0");
export const IP_LOOPBACK = IPAddr.fromString("127.0.0.1");
