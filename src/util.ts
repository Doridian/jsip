import { IPHdr } from "./ip";

export function stringToBuffer(str: string) {
    const buf = new ArrayBuffer(str.length);
    const buf8 = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) {
        buf8[i] = str.charCodeAt(i);
    }
    return buf;
}

export function stringIntoBuffer(str: string, buf: Uint8Array, offset: number) {
    for (let i = 0; i < str.length; i++) {
        buf[i + offset] = str.charCodeAt(i);
    }
}

export function bufferToString(buf: ArrayBuffer, offset: number, len?: number) {
    return arrayToString(new Uint8Array(buf, offset, len));
}

export function arrayToString(buf: Uint8Array) {
    return String.fromCharCode.apply(null, buf);
}

export function buffersToString(bufs: ArrayBuffer[]) {
    let ret = "";
    for (const buf of bufs) {
        ret += bufferToString(buf, 0);
    }
    return ret;
}

export function buffersToBuffer(bufs: ArrayBuffer[] | Uint8Array[]) {
    let curPos = 0;
    for (const buf of bufs) {
        curPos += buf.byteLength;
    }
    const out = new ArrayBuffer(curPos);
    const out8 = new Uint8Array(out);
    curPos = 0;
    for (const buf of bufs) {
        const buf8 = new Uint8Array(buf);
        out8.set(buf8, curPos);
        curPos += buf8.byteLength;
    }
    return out;
}

export function computeChecksumIntermediate(bytes: Uint8Array, csum = 0) {
    for (let i = 0; i < bytes.length; i += 2) {
        csum += bytes[i] + ((bytes[i + 1] || 0) << 8);
    }
    return csum;
}

export function computeChecksumPseudo(ipHdr: IPHdr, proto: number, fullLen: number) {
    const pseudoIP8 = new Uint8Array(12);
    ipHdr.saddr!.toBytes(pseudoIP8, 0);
    ipHdr.daddr!.toBytes(pseudoIP8, 4);
    pseudoIP8[8] = 0;
    pseudoIP8[9] = proto;
    pseudoIP8[10] = (fullLen >>> 8) & 0xFF;
    pseudoIP8[11] = fullLen & 0xFF;
    return computeChecksumIntermediate(pseudoIP8);
}

export function computeChecksum(array: Uint8Array, csum = 0) {
    csum = computeChecksumIntermediate(array, csum);
    csum = (csum >>> 16) + (csum & 0xFFFF);
    return ~csum & 0xFFFF;
}

export function randomByte() {
    return Math.floor(Math.random() * 255);
}

export function boolToBit(bool: boolean, bit: number) {
    return bool ? (1 << bit) : 0;
}

export interface IPacket {
    toPacket(array: ArrayBuffer, offset: number, ipHdr?: IPHdr): number;
    getFullLength(): number;
}
