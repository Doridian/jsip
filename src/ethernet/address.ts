import { randomByte } from "../util/index.js";

function _macPaddedOut(num: number) {
    if (num < 0x10) {
        return `0${num.toString(16)}`;
    }
    return num.toString(16);
}

export class MACAddr {
    public static fromString(macStr: string) {
        const mac = new MACAddr();
        const macS = macStr.split(":");
        mac.a = parseInt(macS[0], 16);
        mac.b = parseInt(macS[1], 16);
        mac.c = parseInt(macS[2], 16);
        mac.d = parseInt(macS[3], 16);
        mac.e = parseInt(macS[4], 16);
        mac.f = parseInt(macS[5], 16);
        return mac;
    }

    public static fromByteArray(macBytes: Uint8Array, offset = 0) {
        const mac = new MACAddr();
        mac.a = macBytes[offset];
        mac.b = macBytes[offset + 1];
        mac.c = macBytes[offset + 2];
        mac.d = macBytes[offset + 3];
        mac.e = macBytes[offset + 4];
        mac.f = macBytes[offset + 5];
        return mac;
    }

    public static fromBytes(a: number, b: number, c: number, d: number, e: number, f: number) {
        const mac = new MACAddr();
        mac.a = a;
        mac.b = b;
        mac.c = c;
        mac.d = d;
        mac.e = e;
        mac.f = f;
        return mac;
    }

    public static fromInt32(macInt: number) {
        const mac = new MACAddr();
        mac.f = macInt & 0xFF;
        mac.e = (macInt >>> 8) & 0xFF;
        mac.d = (macInt >>> 16) & 0xFF;
        mac.c = (macInt >>> 24) & 0xFF;
        mac.b = (macInt >>> 32) & 0xFF;
        mac.a = (macInt >>> 40) & 0xFF;
        return mac;
    }

    public static random() {
        return MACAddr.fromBytes(0x0A,
            randomByte(), randomByte(), randomByte(), randomByte(), randomByte());
    }

    private a = 0;
    private b = 0;
    private c = 0;
    private d = 0;
    private e = 0;
    private f = 0;

    public equals(mac?: MACAddr) {
        if (!mac) {
            return false;
        }
        return mac.a === this.a &&
                mac.b === this.b &&
                mac.c === this.c &&
                mac.d === this.d &&
                mac.e === this.e &&
                mac.f === this.f;
    }

    public toBytes(array: Uint8Array, offset: number) {
        array[offset] = this.a;
        array[offset + 1] = this.b;
        array[offset + 2] = this.c;
        array[offset + 3] = this.d;
        array[offset + 4] = this.e;
        array[offset + 5] = this.f;
    }

    public toInt() {
        return this.f + (this.e << 8) + (this.d << 16) + (this.c << 24) + (this.b << 32) + (this.a << 40);
    }

    public toString() {
        return `${_macPaddedOut(this.a)}:${_macPaddedOut(this.b)}:${_macPaddedOut(this.c)}:` +
                `${_macPaddedOut(this.d)}:${_macPaddedOut(this.e)}:${_macPaddedOut(this.f)}`;
    }

    public isBroadcast() {
        return this.a & 0x01;
    }
}

export const MAC_BROADCAST = MACAddr.fromBytes(255, 255, 255, 255, 255 , 255);
export const MAC_NONE = MACAddr.fromBytes(0, 0, 0, 0, 0, 0);
