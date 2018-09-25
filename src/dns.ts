import { BitArray } from "./bitfield";
import { UDPPkt } from "./udp";
import { boolToBit, bufferToString, stringIntoBuffer } from "./util";
import { IPHdr, IPAddr, IPPROTO } from "./ip";
import { config } from "./config";
import { udpListen } from "./udp_stack";
import { TCPConnectHandler, TCPDisconnectHandler, TCPListener, tcpConnect } from "./tcp_stack";
import { sendPacket } from "./wssend";

type DNSResult = any;
type DNSParseState = { pos: number, data: Uint8Array, packet: ArrayBuffer, offset: number };
type DNSCallback = (result: DNSResult) => void;

const dnsCache: { [key: string]: DNSResult } = {};
const dnsQueue: { [key: string]: DNSCallback[] } = {};
const dnsQueueTimeout: { [key: string]: number } = {};

const DNS_SEG_PTR = 0b11000000;
const DNS_SEG_MAX = 0b00111111;

export const enum DNS_TYPE {
	A = 0x0001,
	CNAME = 0x0005,
	MX = 0x000F,
	NS = 0x0002,
};

export const enum DNS_CLASS {
	IN = 0x0001,
};

export class DNSQuestion {
	public name: string = '';
	public type = DNS_TYPE.A;
	public class = DNS_CLASS.IN;

	write(packet: Uint8Array, pos: number) {
		const nameLbL = makeDNSLabel(this.name);
		for (let i = 0; i < nameLbL.byteLength; i++) {
			packet[pos + i] = nameLbL[i];
		}
		pos += nameLbL.byteLength;

		packet[pos++] = (this.type >>> 8) & 0xFF;
		packet[pos++] = this.type & 0xFF;
		packet[pos++] = (this.class >>> 8) & 0xFF;
		packet[pos++] = this.class & 0xFF;

		return pos;
	}
}

export class DNSAnswer {
	public name: string = '';
	public type = DNS_TYPE.A;
	public class = DNS_CLASS.IN;
	public ttl = 0;
	public data: Uint8Array|undefined = undefined;
	public datapos = 0;

	getTTL() {
		return this.ttl >>> 0;
	}

	write(packet: Uint8Array, pos: number) {
		const nameLbL = makeDNSLabel(this.name);
		for (let i = 0; i < nameLbL.byteLength; i++) {
			packet[pos + i] = nameLbL[i];
		}
		pos += nameLbL.byteLength;

		packet[pos++] = (this.type >>> 8) & 0xFF;
		packet[pos++] = this.type & 0xFF;
		packet[pos++] = (this.class >>> 8) & 0xFF;
		packet[pos++] = this.class & 0xFF;

		packet[pos++] = (this.ttl >>> 24) & 0xFF;
		packet[pos++] = (this.ttl >>> 16) & 0xFF;
		packet[pos++] = (this.ttl >>> 8) & 0xFF;
		packet[pos++] = this.ttl & 0xFF;

		if (this.data) {
			for (let i = 0; i  < this.data.byteLength; i++) {
				packet[pos + i] = this.data[i];
			}
			pos += this.data.byteLength;
		}

		return pos;
	}
}

function parseDNSLabel(s: DNSParseState) {
	const res = [];
	const donePointers: { [key: number]: boolean } = {};
	let lastPos = undefined;
	let dataGood = false;

	while (s.pos < s.data.byteLength) {
		const segLen = s.data[s.pos++];
		if (segLen > DNS_SEG_MAX) {
			if ((segLen & DNS_SEG_PTR) != DNS_SEG_PTR) {
				console.error(`Invalid DNS segment length ${segLen}`);
				break;
			}
			if (lastPos === undefined) {
				lastPos = s.pos + 1;
			}
			s.pos = ((segLen & DNS_SEG_MAX) << 8) | s.data[s.pos];
			if (donePointers[s.pos]) {
				console.error('Recursive pointers detected');
				break;
			}
			donePointers[s.pos] = true;
			continue;
		}

		if (segLen === 0) {
			dataGood = true;
			break;
		}

		res.push(bufferToString(s.packet, s.pos + s.offset, segLen));
		s.pos += segLen;
	}

	if (lastPos !== undefined) {
		s.pos = lastPos;
	}

	if (!dataGood) {
		return null;
	}

	return res.join('.');
}

function makeDNSLabel(str: string) {
	const spl = str.split('.');
	const data = new Uint8Array(str.length + 2); // First len + 0x00 end
	let pos = 0;
	for (let i = 0; i < spl.length; i++) {
		const s = spl[i];
		if (s.length < 1) {
			continue;
		}
		data[pos] = s.length;
		stringIntoBuffer(s, data, pos + 1);
		pos += s.length + 1;
	}
	return data;
}

function parseAnswerSection(count: number, state: DNSParseState) {
	const data = state.data;
	const answers = [];

	for (let i = 0; i < count; i++) {
		const a = new DNSAnswer();

		a.name = parseDNSLabel(state)!;
		if (!a.name) {
			return answers;
		}

		a.type = data[state.pos + 1] + (data[state.pos] << 8);
		a.class = data[state.pos + 3] + (data[state.pos + 2] << 8);
		a.ttl = data[state.pos + 7] + (data[state.pos + 6] << 8) + (data[state.pos + 5] << 16) + (data[state.pos + 4] << 24);
		const rdlength = data[state.pos + 9] + (data[state.pos + 8] << 8);
		state.pos += 10;

		a.datapos = state.pos;
		a.data = new Uint8Array(state.packet, state.offset + state.pos, rdlength);
		state.pos += rdlength;

		answers.push(a);
	}

	return answers;
}

export class DNSPkt {
	public id = 0;
	public qr = false;
	public opcode = 0;
	public aa = false;
	public tc = false;
	public rd = true;
	public ra = false;
	public rcode = 0;
	public questions: DNSQuestion[] = []; // QDCOUNT
	public answers: DNSAnswer[] = []; // ANCOUNT
	public authority: DNSAnswer[] = []; // NSCOUNT
	public additional: DNSAnswer[] = []; // ARCOUNT

	static fromPacket(packet: ArrayBuffer, offset: number) {
		const data = new Uint8Array(packet, offset);
		const bit = new BitArray(packet, offset + 2);

		const dns = new DNSPkt();
		dns.id = data[1] + (data[0] << 8);
		
		// [2]
		dns.qr = bit.bool();
		dns.opcode = bit.read(4);
		dns.aa = bit.bool();
		dns.tc = bit.bool();
		dns.rd = bit.bool();

		// [3]
		dns.ra = bit.bool();
		bit.skip(3);
		dns.rcode = bit.read(4);

		const qdcount = data[5] + (data[4] << 8);
		const ancount = data[7] + (data[6] << 8);
		const nscount = data[9] + (data[8] << 8);
		const arcount = data[11] + (data[10] << 8);

		dns.questions = [];
		const state = { pos: 12, data, packet, offset };
		for (let i = 0; i < qdcount; i++) {
			const q = new DNSQuestion();
			q.name = parseDNSLabel(state)!;
			q.type = data[state.pos + 1] + (data[state.pos] << 8);
			q.class = data[state.pos + 3] + (data[state.pos + 2] << 8);
			state.pos += 4;
			dns.questions.push(q);
		}

		dns.answers = parseAnswerSection(ancount, state);
		dns.authority = parseAnswerSection(nscount, state);
		dns.additional = parseAnswerSection(arcount, state);

		return dns;
	}

	getFullLength() {
		let len = 12;
		this.questions.forEach(q => {
			len += (q.name.length + 2) + 4;
		});
		this.answers.forEach(a => {
			len += (a.name.length + 2) + 10 + (a.data ? a.data.byteLength : 0);
		});
		this.authority.forEach(a => {
			len += (a.name.length + 2) + 10 + (a.data ? a.data.byteLength : 0);
		});
		this.additional.forEach(a => {
			len += (a.name.length + 2) + 10 + (a.data ? a.data.byteLength : 0);
		});
		return len;
	}

	toPacket(array: ArrayBuffer, offset: number) {
		return this._toPacket(new Uint8Array(array, offset));
	}

	toBytes() {
		const packet = new Uint8Array(this.getFullLength());
		this._toPacket(packet);
		return packet;
	}

	_toPacket(packet: Uint8Array) {
		packet[0] = (this.id >>> 8) & 0xFF;
		packet[1] = this.id & 0xFF;
		packet[2] = boolToBit(this.qr, 7) | (this.opcode << 3) | boolToBit(this.aa, 2) | boolToBit(this.tc, 1) | boolToBit(this.rd, 0);
		packet[3] = boolToBit(this.ra, 7) | this.rcode;

		const qdcount = this.questions.length;
		const ancount = this.answers.length;
		const nscount = this.authority.length;
		const arcount = this.additional.length;

		packet[4] = (qdcount >>> 8) & 0xFF;
		packet[5] = qdcount & 0xFF;
		packet[6] = (ancount >>> 8) & 0xFF;
		packet[7] = ancount & 0xFF;
		packet[8] = (nscount >>> 8) & 0xFF;
		packet[9] = nscount & 0xFF;
		packet[10] = (arcount >>> 8) & 0xFF;
		packet[11] = arcount & 0xFF;

		let pos = 12;

		for (let i = 0; i < qdcount; i++) {
			pos = this.questions[i].write(packet, pos);
		}
		for (let i = 0; i < ancount; i++) {
			pos = this.answers[i].write(packet, pos);
		}
		for (let i = 0; i < nscount; i++) {
			pos = this.authority[i].write(packet, pos);
		}
		for (let i = 0; i < arcount; i++) {
			pos = this.additional[i].write(packet, pos);
		}

		return pos;
	}
}

function makeDNSRequest(domain: string, type: DNS_TYPE) {
	const pkt = new DNSPkt();
	const q = new DNSQuestion();
	q.type = type;
	q.name = domain;
	pkt.questions = [q];
	pkt.id = Math.floor(Math.random() * 0xFFFF);
	return makeDNSUDP(pkt);
}

function makeDNSUDP(dns: DNSPkt) {
	const pkt = new UDPPkt();
	pkt.data = dns.toBytes();
	pkt.sport = 53;
	pkt.dport = 53;
	return pkt;
}

function makeDNSIP() {
	const ip = new IPHdr();
	ip.protocol = IPPROTO.UDP;
	ip.saddr = config.ourIp;
	ip.daddr = config.dnsServerIps[0];
	ip.df = false;
	return ip;
}

function _makeDNSCacheKey(domain: string, type: DNS_TYPE) {
	return `${type},${domain}`;
}

function domainCB(domain: string, type: number, result: DNSResult) {
	const _key = _makeDNSCacheKey(domain, type);
	if (result) {
		dnsCache[_key] = result;
	} else {
		delete dnsCache[_key];
	}

	if (dnsQueue[_key]) {
		dnsQueue[_key].forEach(cb => cb(result));
		delete dnsQueue[_key];
	}

	if (dnsQueueTimeout[_key]) {
		clearTimeout(dnsQueueTimeout[_key]);
		delete dnsQueueTimeout[_key];
	}
}

udpListen(53, (data: Uint8Array|undefined, _ipHdr: IPHdr) => {
	if (!data) {
		return;
	}

	const packet = data.buffer;
	const offset = data.byteOffset;

	const dns = DNSPkt.fromPacket(packet, offset);
	if (!dns || !dns.qr) {
		return;
	}

	const _parseDNSLabel = (pos: number) => {
		return parseDNSLabel({ offset: 0, packet, data, pos });
	};

	// This could clash if asked for ANY, but ANY is deprecated
	const answerMap: { [key: string]: DNSAnswer } = {};
	dns.answers.forEach(a => {
		if (a.class !== DNS_CLASS.IN) {
			return;
		}

		answerMap[a.name] = a;
	});

	dns.questions.forEach(q => {
		if (q.class !== DNS_CLASS.IN) {
			return;
		}

		const domain = q.name;
		let answer = answerMap[domain];
		while (answer && answer.type === DNS_TYPE.CNAME && q.type !== DNS_TYPE.CNAME) {
			const cnameTarget = _parseDNSLabel(answer.datapos)!;
			answer = answerMap[cnameTarget];
		}

		if (!answer || answer.type !== q.type) {
			domainCB(domain, q.type, undefined);
			return;
		}

		let _answer = undefined;
		switch (q.type) {
			case DNS_TYPE.CNAME:
			case DNS_TYPE.NS:
				_answer = _parseDNSLabel(answer.datapos);
				break;
			case DNS_TYPE.A:
				_answer = IPAddr.fromByteArray(answer.data!);
				break;
		}
		domainCB(domain, q.type, _answer);
	});
});

export function dnsResolve(domain: string, type: DNS_TYPE, cb: DNSCallback) {
	domain = domain.toLowerCase();
	const _key = _makeDNSCacheKey(domain, type);

	if (dnsCache[_key]) {
		cb(dnsCache[_key]);
		return;
	}

	if (dnsQueue[_key]) {
		dnsQueue[_key].push(cb);
		return;
	}
	
	dnsQueue[_key] = [cb];
	dnsQueueTimeout[_key] = setTimeout(() => {
		delete dnsQueueTimeout[_key];
		domainCB(domain, type, undefined);
	}, 10000);

	sendPacket(makeDNSIP(), makeDNSRequest(domain, type));
}

const IP_REGEX = /^\d+\.\d+\.\d+\.\d+$/;

export function dnsResolveOrIp(domain: string, cb: DNSCallback) {
	if (IP_REGEX.test(domain)) {
		cb(IPAddr.fromString(domain));
		return;
	}

	dnsResolve(domain, DNS_TYPE.A, cb);
}

export function dnsTcpConnect(domainOrIp: string, port: number, func: TCPListener, cb: TCPConnectHandler, dccb: TCPDisconnectHandler) {
	dnsResolveOrIp(domainOrIp, (ip: IPAddr) => {
		if (!ip) {
			cb(false, undefined);
			return;
		}
		tcpConnect(ip, port, func, cb, dccb);
	});
}
