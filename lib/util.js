'use strict';

function computeChecksumIntermediate(array, offset, len, csum = 0) {
	const bytes = new Uint8Array(array, offset, len);
	for (let i = 0; i < bytes.length; i += 2) {
		csum += bytes[i] + ((bytes[i + 1] || 0) << 8);
	}
	return csum;
}

function computeChecksum(array, offset, len, csum = 0) {
	csum = computeChecksumIntermediate(array, offset,len, csum);
	csum = (csum >>> 16) + (csum & 0xFFFF);
	return ~csum & 0xFFFF;
}

class IHdr {
	constructor(fill = true) {
		if (fill) {
			this.fill();
		}
	}

	fill() {
	}
}
