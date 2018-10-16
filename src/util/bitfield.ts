export class BitArray {
    public pos: number;
    private data: Uint8Array;

    constructor(data: ArrayBuffer, offset: number) {
        this.data = new Uint8Array(data, offset);
        this.pos = 0;
    }

    public skip(len: number) {
        this.pos += len;
    }

    public read(len: number) {
        const ret = (this.data[this.pos >>> 3] >> (8 - (this.pos & 7) - len)) & ((1 << len) - 1);
        this.pos += len;
        return ret;
    }

    public bool() {
        return this.read(1) !== 0;
    }
}
