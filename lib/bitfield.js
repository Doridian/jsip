'use strict';

class BitArray {
	constructor(data, offset) {
		this.data = new Uint8Array(data, offset);
		this.pos = 0;
	}

	get(pos, len) {
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

	read(len) {
		const ret = this.get(this.pos, len);
		this.pos += len;
		return ret;
	}

	reset() {
		this.pos = 0;
	}
}
