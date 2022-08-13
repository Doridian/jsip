import { randomByte } from "../util/index";

function macPaddedOut(num: number) {
    if (num < 0x10) {
        return `0${num.toString(16)}`;
    }
    return num.toString(16);
}

export class MACAddr {
    public static fromString(macStr: string) {
        const mac = new MACAddr();
        const macS = macStr.split(":");
        macS.forEach((str, i) => {
            mac.raw[i] = parseInt(str, 16);
        });
        return mac;
    }

    public static fromByteArray(macBytes: ArrayLike<number>, offset = 0) {
        const mac = new MACAddr();
        mac.raw[0] = macBytes[offset];
        mac.raw[1] = macBytes[offset + 1];
        mac.raw[2] = macBytes[offset + 2];
        mac.raw[3] = macBytes[offset + 3];
        mac.raw[4] = macBytes[offset + 4];
        mac.raw[5] = macBytes[offset + 5];
        return mac;
    }

    public static fromInt32(macInt: number) {
        const mac = new MACAddr();
        mac.raw[0] = (macInt >>> 40) & 0xFF;
        mac.raw[1] = (macInt >>> 32) & 0xFF;
        mac.raw[2] = (macInt >>> 24) & 0xFF;
        mac.raw[3] = (macInt >>> 16) & 0xFF;
        mac.raw[4] = (macInt >>> 8) & 0xFF;
        mac.raw[5] = macInt & 0xFF;
        return mac;
    }

    public static random() {
        return MACAddr.fromByteArray([0x0A,
            randomByte(), randomByte(), randomByte(), randomByte(), randomByte()]);
    }

    private raw = new Uint8Array(6);

    public equals(mac?: MACAddr) {
        if (!mac) {
            return false;
        }
        return this.raw.every((val, idx) => val === mac.raw[idx]);
    }

    public toBytes(array: Uint8Array, offset: number) {
        array[offset] = this.raw[0];
        array[offset + 1] = this.raw[1];
        array[offset + 2] = this.raw[2];
        array[offset + 3] = this.raw[3];
        array[offset + 4] = this.raw[4];
        array[offset + 5] = this.raw[5];
    }

    public toString() {
        return `${macPaddedOut(this.raw[0])}:${macPaddedOut(this.raw[1])}:${macPaddedOut(this.raw[2])}:` +
                `${macPaddedOut(this.raw[3])}:${macPaddedOut(this.raw[4])}:${macPaddedOut(this.raw[5])}`;
    }

    public isBroadcast() {
        return this.raw[0] & 0x01;
    }
}

export const MAC_BROADCAST = MACAddr.fromByteArray([255, 255, 255, 255, 255, 255]);
export const MAC_NONE = MACAddr.fromByteArray([0, 0, 0, 0, 0, 0]);
