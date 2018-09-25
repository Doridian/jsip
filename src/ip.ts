import { computeChecksum } from './util';
import { BitArray } from './bitfield';
import { config } from './config';

export const enum IPPROTO {
	NONE = 0,
	ICMP = 1,
	TCP = 6,
	UDP = 17,
};

export class IPAddr {
	private a = 0;
	private b = 0;
	private c = 0;
	private d = 0;

	static fromString(ipStr: string) {
		const ip = new IPAddr();
		const ipS = ipStr.split('.');
		ip.a = parseInt(ipS[0], 10);
		ip.b = parseInt(ipS[1], 10);
		ip.c = parseInt(ipS[2], 10);
		ip.d = parseInt(ipS[3], 10);
		return ip;
	}

	static fromByteArray(ipBytes: Uint8Array, offset = 0) {
		const ip = new IPAddr();
		ip.a = ipBytes[offset];
		ip.b = ipBytes[offset + 1];
		ip.c = ipBytes[offset + 2];
		ip.d = ipBytes[offset + 3];
		return ip;
	}

	static fromBytes(a: number, b: number, c: number, d: number) {
		const ip = new IPAddr();
		ip.a = a;
		ip.b = b;
		ip.c = c;
		ip.d = d;
		return ip;
	}

	static fromInt32(ipInt: number) {
		const ip = new IPAddr();
		ip.d = ipInt & 0xFF;
		ip.c = (ipInt >>> 8) & 0xFF;
		ip.b = (ipInt >>> 16) & 0xFF;
		ip.a = (ipInt >>> 24) & 0xFF;
		return ip;
	}

	equals(ip?: IPAddr) {
		if (!ip) {
			return false;
		}
		return ip.a === this.a && ip.b === this.b && ip.c === this.c && ip.d === this.d;
	}

	toBytes(array: Uint8Array, offset: number) {
		array[offset] = this.a;
		array[offset + 1] = this.b;
		array[offset + 2] = this.c;
		array[offset + 3] = this.d;
	}

	toByteArray() {
		const res = new Uint8Array(4);
		this.toBytes(res, 0);
		return res;
	}

	toInt() {
		return this.d + (this.c << 8) + (this.b << 16) + (this.a << 24);
	}

	toString() {
		return `${this.a}.${this.b}.${this.c}.${this.d}`;
	}

	isMulticast() {
		return IPNETS_MULTICAST.some(net => net.contains(this));
	}

	isBroadcast() {
		return this.equals(IP_BROADCAST);
	}

	isUnicast() {
		return !this.isBroadcast() && !this.isMulticast();
	}
}

export class IPNet {
	public ip?: IPAddr;
	private bitmask = 0;
	private mask?: IPAddr;
	private baseIpInt = 0;

	static fromString(ipStr: string) {
		const ipS = ipStr.split('/');
		const ip = IPAddr.fromString(ipS[0]);
		const subnetLen = parseInt(ipS[1], 10);
		return new IPNet(ip, ~((1 << (32 - subnetLen)) - 1));
	}

	constructor(ip: IPAddr, bitmask: number) {
		this.ip = ip;
		this.bitmask = bitmask;
		this.mask = IPAddr.fromInt32(bitmask);
		this.baseIpInt = ip.toInt() & bitmask;
	}

	equals(ipNet: IPNet) {
		if (!ipNet) {
			return false;
		}
		return this.bitmask === ipNet.bitmask && this.ip!.equals(ipNet.ip!);
	}

	toString() {
		return `${this.ip}/${this.mask}`;
	}

	contains(ip?: IPAddr) {
		if (!ip) {
			return false;
		}
		return (ip.toInt() & this.bitmask) === this.baseIpInt;
	}

	getAddress(num: number) {
		return IPAddr.fromInt32(this.baseIpInt + num);
	}
}

export class IPHdr {
	private version = 4;
	public ihl = 5;
	public dscp = 0;
	public ecn = 0;
	public len = 0;
	public id = 0;
	public df = false;
	public mf = false;
	public frag_offset = 0;
	private ttl = 64;
	public protocol = IPPROTO.NONE;
	private checksum = 0;
	public saddr?: IPAddr;
	public daddr?: IPAddr;
	public options?: ArrayBuffer;

	static fromPacket(packet: ArrayBuffer, offset: number) {
		const ipv4 = new IPHdr();
		const bit = new BitArray(packet, offset);
		ipv4.version = bit.read(4);
		if (ipv4.version !== 4) {
			return null;
		}
		ipv4.ihl = bit.read(4);
		ipv4.dscp = bit.read(6);
		ipv4.ecn = bit.read(2);
		ipv4.len = bit.read(16);
		ipv4.id = bit.read(16);
		const flags = bit.read(3);
		ipv4.df = (flags & 0x2) === 0x2;
		ipv4.mf = (flags & 0x1) === 0x1;
		ipv4.frag_offset = bit.read(13);
		ipv4.ttl = bit.read(8);
		ipv4.protocol = bit.read(8);
		ipv4.checksum = bit.read(16);
		ipv4.saddr = IPAddr.fromBytes(bit.read(8), bit.read(8), bit.read(8), bit.read(8));
		ipv4.daddr = IPAddr.fromBytes(bit.read(8), bit.read(8), bit.read(8), bit.read(8));
		const oLen = ipv4.ihl << 2;
		if (oLen > 20) {
			const oBeg = (bit.pos >>> 3) + offset;
			ipv4.options = packet.slice(oBeg, oBeg + (oLen - 20));
		} else {
			ipv4.options = new ArrayBuffer(0);
		}
		const checksum = computeChecksum(new Uint8Array(packet, offset, oLen));
		if (checksum !== 0) {
			console.error(`Invalid IPv4 checksum: ${checksum} !== 0`, ipv4);
			return null;
		}
		return ipv4;
	}

	setContentLength(len: number) {
		this.len = this.getContentOffset() + len;
	}

	getContentLength() {
		return this.len - this.getContentOffset();
	}

	getFullLength() {
		return this.len;
	}

	getContentOffset() {
		return this.ihl << 2;
	}

	makeReply() {
		const replyIp = new IPHdr();
		replyIp.protocol = this.protocol;
		if (this.daddr!.isUnicast()) {
			replyIp.saddr = this.daddr;
		} else {
			replyIp.saddr = config.ourIp;
		}
		replyIp.daddr = this.saddr;
		return replyIp;
	}

	toPacket(array: ArrayBuffer, offset: number) {
		const packet = new Uint8Array(array, offset, (this.options ? this.options.byteLength : 0) + 20);
		this.ihl = packet.length >>> 2;
		packet[0] = ((this.version & 0xF) << 4) + (this.ihl & 0xF);
		packet[1] = ((this.dscp & 0xFC) << 2) + (this.ecn & 0x3);
		packet[2] = (this.len >>> 8) & 0xFF;
		packet[3] = this.len & 0xFF;
		packet[4] = (this.id >>> 8) & 0xFF;
		packet[5] = this.id & 0xFF;
		const flags = (this.df ? 0x2 : 0x0) + (this.mf ? 0x1 : 0x0);
		packet[6] = (flags << 5) + ((this.frag_offset >>> 8) & 0x1F);
		packet[7] = this.frag_offset & 0xFF;
		packet[8] = this.ttl & 0xFF;
		packet[9] = this.protocol & 0xFF;
		packet[10] = 0; // Checksum A
		packet[11] = 0; // Checksum B
		this.saddr!.toBytes(packet, 12);
		this.daddr!.toBytes(packet, 16);
		if (this.options && this.options.byteLength > 0) {
			const o8 = new Uint8Array(this.options);
			for (let i = 0; i < o8.length; i++) {
				packet[i + 12] = o8[i];
			}
		}
		this.checksum = computeChecksum(packet);
		packet[10] = this.checksum & 0xFF;
		packet[11] = (this.checksum >>> 8) & 0xFF;
		return packet.length;
	}
}

export const IP_BROADCAST = IPAddr.fromString('255.255.255.255');
export const IP_NONE = IPAddr.fromString('0.0.0.0');

const IPNETS_MULTICAST = [
	IPNet.fromString('224.0.0.0/14'),
	IPNet.fromString('224.4.0.0/16'),
	IPNet.fromString('232.0.0.0/8'),
	IPNet.fromString('233.0.0.0/8'),
	IPNet.fromString('234.0.0.0/8'),
	IPNet.fromString('239.0.0.0/8'),
];
