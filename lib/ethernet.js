'use strict';

function _macPaddedOut(num) {
	if (num < 0x10) {
		return `0${num.toString(16)}`;
	}
	return num.toString(16);
}

class MACAddr {
	static fromString(macStr) {
		const mac = new MACAddr();
		const macS = macStr.split(':');
		mac.a = parseInt(macS[0], 16);
		mac.b = parseInt(macS[1], 16);
		mac.c = parseInt(macS[2], 16);
		mac.d = parseInt(macS[3], 16);
		mac.d = parseInt(macS[4], 16);
		mac.d = parseInt(macS[5], 16);
		return mac;
	}

	static fromByteArray(macBytes, offset = 0) {
		const mac = new MACAddr();
		mac.a = macBytes[offset];
		mac.b = macBytes[offset + 1];
		mac.c = macBytes[offset + 2];
		mac.d = macBytes[offset + 3];
		mac.e = macBytes[offset + 4];
		mac.f = macBytes[offset + 5];
		return mac;
	}

	static fromBytes(a, b, c, d, e, f) {
		const mac = new MACAddr();
		mac.a = a;
		mac.b = b;
		mac.c = c;
		mac.d = d;
		mac.e = e;
		mac.f = f;
		return mac;
	}

	static fromInt32(macInt) {
		const mac = new MACAddr();
		mac.f = ipInt & 0xFF;
		mac.e = (ipInt >>> 8) & 0xFF;
		mac.d = (ipInt >>> 16) & 0xFF;
		mac.c = (ipInt >>> 24) & 0xFF;
		mac.b = (ipInt >>> 32) & 0xFF;
		mac.a = (ipInt >>> 40) & 0xFF;
		return mac;
	}

	equals(mac) {
		return mac.a === this.a && mac.b === this.b && mac.c === this.c && mac.d === this.d && mac.e === this.e && mac.f === this.f;
	}

	toBytes(array, offset) {
		array[offset] = this.a;
		array[offset + 1] = this.b;
		array[offset + 2] = this.c;
		array[offset + 3] = this.d;
		array[offset + 4] = this.e;
		array[offset + 5] = this.f;
	}

	toInt() {
		return this.f + (this.e << 8) + (this.d << 16) + (this.c << 24) + (this.b << 32) + (this.a << 40);
	}

	toString() {
		return `${_macPaddedOut(this.a)}:${_macPaddedOut(this.b)}:${_macPaddedOut(this.c)}:${_macPaddedOut(this.d)}:${_macPaddedOut(this.e)}:${_macPaddedOut(this.f)}`;
	}
}

const MAC_BROADCAST = MACAddr.fromBytes(255, 255, 255, 255, 255 , 255);

const ETH_IP  = 0x0800;
const ETH_IP6 = 0x86DD;
const ETH_ARP = 0x0806;

const ETH_LEN = 14;

class EthHdr extends IHdr {
	fill() {
		this.ethtype = 0;
		this.saddr = null;
		this.daddr = null;
	}

	makeReply() {
		const replyEth = new EthHdr();
		replyEth.ethtype = this.ethtype;
		replyEth.saddr = this.daddr;
		replyEth.daddr = this.saddr;
		return replyEth;
	}

	static fromPacket(packet, offset) {
		const eth = new EthHdr(false);
		const data = new Uint8Array(packet, offset);
		eth.daddr = MACAddr.fromByteArray(data, 0);
		eth.saddr = MACAddr.fromByteArray(data, 6);
		eth.ethtype = data[13] + (data[12] << 8);
		return eth;
	}

	getContentOffset() {
		return ETH_LEN;
	}

	toPacket(array, offset) {
		const packet = new Uint8Array(array, offset, ETH_LEN);
		this.daddr.toBytes(packet, 0);
		this.saddr.toBytes(packet, 6);
		packet[12] = (this.ethtype >>> 8) & 0xFF;
		packet[13] = this.ethtype & 0xFF;
		return ETH_LEN;
	}
}
