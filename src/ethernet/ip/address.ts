export class IPAddr {
    public static fromString(ipStr: string) {
        const ip = new IPAddr();
        const ipS = ipStr.split('.');
        if (ipS.length !== 4) {
            throw new Error("Invalid IPv4 address");
        }
        for (let i = 0; i < 4; i++) {
            ip.raw[3 - i] = parseInt(ipS[i]!, 10);
        }
        return ip;
    }

    public static fromByteArray(array: ArrayLike<number>, offset = 0) {
        const ip = new IPAddr();
        ip.raw[3] = array[offset]!;
        ip.raw[2] = array[1 + offset]!;
        ip.raw[1] = array[2 + offset]!;
        ip.raw[0] = array[3 + offset]!;
        return ip;
    }

    public static fromInt32(ipInt: number) {
        const ip = new IPAddr();
        ip.raw32[0] = ipInt;
        return ip;
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
        array[offset] = this.raw[3]!;
        array[1 + offset] = this.raw[2]!;
        array[2 + offset] = this.raw[1]!;
        array[3 + offset] = this.raw[0]!;
    }

    public toByteArray() {
        const res = new Uint8Array(4);
        this.toBytes(res, 0);
        return res;
    }

    public toInt32() {
        return this.raw32[0]!;
    }

    public toString() {
        return `${this.raw[3]}.${this.raw[2]}.${this.raw[1]}.${this.raw[0]}`;
    }

    public isMulticast() {
        return this.raw[3]! >= 224 && this.raw[3]! <= 239;
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

export const IP_NULL = IPAddr.fromString("0.0.0.0");
export const IP_BROADCAST = IPAddr.fromString("255.255.255.255");
export const IP_LOOPBACK = IPAddr.fromString("127.0.0.1");
