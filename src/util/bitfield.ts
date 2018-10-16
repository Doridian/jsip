export class BitArray {
    public pos: number;
    private data: Uint8Array;

    constructor(data: ArrayBuffer, offset: number) {
        this.data = new Uint8Array(data, offset);
        this.pos = 0;
    }

    public get(pos: number, len: number) {
        if (len < 1 || len >= 8 || !isFinite(len)) {
            throw new RangeError("len must be between 1 and 7 inclusive");
        }

        const byteIndex = pos >>> 3;
        const offset = pos & 7;
        if (offset + len > 8) {
            throw new RangeError(`Cannot read accross byte boundaries; ${offset}; ${len}; ${pos}`);
        }

        const curData = this.data[byteIndex];
        const mask = (1 << len) - 1;
        const shift = 8 - offset - len;
        return (curData >> shift) & mask;
    }

    public skip(len: number) {
        this.pos += len;
    }

    public read(len: number) {
        const ret = this.get(this.pos, len);
        this.pos += len;
        return ret;
    }

    public bool() {
        return this.read(1) !== 0;
    }

    public reset() {
        this.pos = 0;
    }
}
