import { buffersToBuffer, CHAR_LF } from "./string.js";

export class Buffer {
  private data: Uint8Array[] = [];
  private len = 0;
  private lastReadDelim = -1;
  private lastReadEnd = 0;
  private lastStartPosOffset = 0;

  public add(data: Uint8Array) {
    this.data.push(data);
    this.len += data.length;
  }

  public reset() {
    this.data = [];
    this.len = 0;
    this.lastReadDelim = -1;
    this.lastReadEnd = 0;
    this.lastStartPosOffset = 0;
  }

  public length() {
    return this.len;
  }

  public readLine() {
    return this.readUntil(CHAR_LF);
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
      const data = this.data[i]!;

      const startPos = data.indexOf(delim);
      if (startPos !== -1) {
        return this.read(startPosOffset + startPos + 1);
      }

      startPosOffset += data.length;
    }

    this.lastStartPosOffset = startPosOffset;
    this.lastReadEnd = this.data.length;

    throw new BufferNotEnoughDataError();
  }

  public readAll() {
    if (this.len < 1) {
      return new Uint8Array(0);
    }

    const res = new Uint8Array(buffersToBuffer(this.data));
    this.reset();
    return res;
  }

  public read(len: number) {
    if (!isFinite(len)) {
      throw new TypeError(`Invalid length: ${len}`);
    }

    if (len <= 0) {
      return new Uint8Array(0);
    }

    if (len > this.len) {
      throw new BufferNotEnoughDataError();
    }

    this.lastReadDelim = -1; // Invalidate state of readUntil

    const res = new Uint8Array(len);
    let dataLeft = len;
    let pos = 0;
    while (dataLeft > 0) {
      const d = this.data[0]!;
      if (d.length > dataLeft) {
        res.set(new Uint8Array(d.buffer, d.byteOffset, dataLeft), pos);
        this.data[0] = new Uint8Array(
          d.buffer,
          d.byteOffset + dataLeft,
          d.length - dataLeft,
        );
        break;
      }
      res.set(d, pos);
      this.data.shift();
      dataLeft -= d.length;
      pos += d.length;
    }

    this.len -= len;

    return res;
  }
}

export class BufferNotEnoughDataError extends Error {
  public constructor() {
    super();
    this.name = "BufferNotEnoughDataError";
  }
}
