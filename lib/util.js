'use strict';

function computeChecksum(array, offset, len) {
	const bytes = new Uint8Array(array, offset, len);
	let csum = 0;
	for (let i = 0; i < bytes.length; i += 2) {
		csum += bytes[i] + (bytes[i + 1] << 8);
	}
	return ~csum & 0xFFFF;
}

