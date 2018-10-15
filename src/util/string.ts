export const CHAR_CR = "\r".charCodeAt(0);
export const CHAR_LF = "\n".charCodeAt(0);

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
    return String.fromCharCode.apply(null, buf) as string;
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
        if (buf8.byteLength < 1) {
            continue;
        }

        out8.set(buf8, curPos);
        curPos += buf8.byteLength;
    }
    return out;
}
