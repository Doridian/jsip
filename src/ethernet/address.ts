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
        macS.forEach((str, i) => {
            mac.raw[i] = parseInt(str, 16);
        });
        return mac;
    }

    public static fromByteArray(macBytes: ArrayLike<number>, offset = 0) {
        const mac = new MACAddr();
        for (let i = 0; i < 6; i++) {
            mac.raw[i] = macBytes[i + offset];
        }
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
        const subArray = new Uint8Array(array.buffer, array.byteOffset + offset, 6);
        subArray.set(this.raw, 0);
    }

    public toString() {
        return `${_macPaddedOut(this.raw[0])}:${_macPaddedOut(this.raw[1])}:${_macPaddedOut(this.raw[2])}:` +
                `${_macPaddedOut(this.raw[3])}:${_macPaddedOut(this.raw[4])}:${_macPaddedOut(this.raw[5])}`;
    }

    public isBroadcast() {
        return this.raw[0] & 0x01;
    }
}

export const MAC_BROADCAST = MACAddr.fromByteArray([255, 255, 255, 255, 255, 255]);
export const MAC_NONE = MACAddr.fromByteArray([0, 0, 0, 0, 0, 0]);
