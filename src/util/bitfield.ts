export class BitArray {
    public pos: number;
    private data: Uint8Array;

    constructor(data: ArrayBuffer, offset: number) {
        this.data = new Uint8Array(data, offset);
        this.pos = 0;
    }

    public get(pos: number, len: number) {
        let byteIndex = pos >>> 3;
        if (len === 8 && (pos % 8) === 0) {
            return this.data[byteIndex];
        }
        const shift = 24 - (pos & 7) - len;
        const mask = (1 << len) - 1;
        return (
            ((this.data[byteIndex]   << 16) |
             (this.data[++byteIndex] <<  8) |
              this.data[++byteIndex]
            ) >> shift
        ) & mask;
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
