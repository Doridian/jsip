'use strict';

function computeChecksumIntermediate(array, offset, len, csum = 0) {
	const bytes = new Uint8Array(array, offset, len);
	for (let i = 0; i < bytes.length; i += 2) {
		csum += bytes[i] + ((bytes[i + 1] || 0) << 8);
	}
	return csum;
}

function computeChecksumPseudo(ipHdr, proto, fullLen) {
	const pseudoIP8 = new Uint8Array(12);
	ipHdr.saddr.toBytes(pseudoIP8, 0);
	ipHdr.daddr.toBytes(pseudoIP8, 4);
	pseudoIP8[8] = 0;
	pseudoIP8[9] = proto;
	pseudoIP8[10] = (fullLen >>> 8) & 0xFF;
	pseudoIP8[11] = fullLen & 0xFF;
	return computeChecksumIntermediate(pseudoIP8.buffer, 0, 12);
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
