type ParseFunction<T> = (self: CheckpointStream<T>, state?: T) => T | undefined;

export class CheckpointStream<T> {
    public parseOnAdd = false;
    public parseRepeat = false;
    private data: Uint8Array[] = [];
    private len: number = 0;
    private state: T;
    private parseFunc: ParseFunction<T>;
    private lastReadDelim = -1;
    private lastReadEnd = -1;
    private lastStartPosOffset = 0;

    constructor(parseFunc: ParseFunction<T>, defaultState: T) {
        this.parseFunc = parseFunc;
        this.state = defaultState;
    }

    public add(data: Uint8Array) {
        this.data.push(data);
        this.len += data.length;

        if (this.parseOnAdd) {
            this.parse();
        }
    }

    public setState(state: T) {
        this.state = state;
    }

    public parse() {
        try {
            do {
                const res = this.parseFunc(this, this.state);
                if (res !== undefined) {
                    this.state = res;
                }
            } while (this.parseRepeat);
        } catch (e) {
            if (e instanceof StreamNotEnoughDataError) {
                return;
            }
            throw e;
        }
    }

    public readUntil(delim: number) {
        if (delim < 0) {
            throw new Error("Delim must be >= 0");
        }

        const reuseLast = this.lastReadDelim === delim;

        let startPosOffset = reuseLast ? this.lastStartPosOffset : 0;

        if (!reuseLast) {
            this.lastReadDelim = delim;
        }

        for (let i = reuseLast ? this.lastReadEnd : 0; i < this.data.length; i++) {
            const data = this.data[i];

            const startPos = data.findIndex((elem) => elem === delim);
            if (startPos >= 0) {
                return this.read(startPosOffset + startPos + 1);
            }

            startPosOffset += data.length;
        }

        this.lastStartPosOffset = startPosOffset;
        this.lastReadEnd = this.data.length;

        throw new StreamNotEnoughDataError();
    }

    public read(len: number) {
        if (len > this.len) {
            throw new StreamNotEnoughDataError();
        }

        this.lastReadDelim = -1; // Invalidate state of readUntil

        const res = new Uint8Array(len);
        let dataLeft = len;
        let pos = 0;
        while (dataLeft > 0) {
            const d = this.data[0];
            if (d.byteLength > dataLeft) {
                res.set(new Uint8Array(d.buffer, d.byteOffset, dataLeft), pos);
                this.data[0] = new Uint8Array(d.buffer, d.byteOffset + dataLeft, d.byteLength - dataLeft);
                break;
            }
            res.set(d, pos);
            this.data.shift();
            dataLeft -= d.byteLength;
            pos += d.byteLength;
        }

        this.len -= len;

        return res;
    }
}

// tslint:disable-next-line:max-classes-per-file
export class StreamNotEnoughDataError extends Error {

}
