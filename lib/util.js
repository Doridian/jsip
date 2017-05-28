'use strict';

function computeChecksum(array, offset, len) {
	const bytes = new Uint8Array(array, offset, len);
	let csum = 0;
	for (let i = 0; i < bytes.length; i += 2) {
		csum += bytes[i] + ((bytes[i + 1] || 0) << 8);
	}
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
