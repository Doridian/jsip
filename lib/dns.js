'use strict';

const dnsCache = {};
const dnsQueue = {};

const DNS_TYPE_A = 0x0001;
const DNS_TYPE_MX = 0x000F;
const DNS_TYPE_NS = 0x0002;

const DNS_CLASS_IN = 0x0001;

class DNSQuestion extends IHdr {
	fill() {
		this.name = '';
		this.type = DNS_TYPE_A;
		this.class = DNS_CLASS_IN;
	}

	write(packet, pos) {
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

class DNSAnswer extends IHdr {
	fill() {
		this.name = '';
		this.type = DNS_TYPE_A;
		this.class = DNS_CLASS_IN;
		this.ttl = 0;
		this.data = new Uint8Array(0);
	}

	getTTL() {
		return this.ttl >>> 0;
	}

	write(packet, pos) {
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

		for (let i = 0; i  < this.data.byteLength; i++) {
			packet[pos + i] = this.data[i];
		}
		pos += this.data.byteLength;

		return pos;
	}
}

const DNS_SEG_PTR = 0b11000000;
const DNS_SEG_MAX = 0b00111111;

function parseDNSLabel(s) {
	const res = [];
	let lastPos = undefined;

	while (s.pos < s.data.byteLength) {
		const segLen = s.data[s.pos++];
		if (segLen > DNS_SEG_MAX) {
			if ((segLen & DNS_SEG_PTR) != DNS_SEG_PTR) {
				console.error(`Invalid DNS segment length ${segLen}`);
				return null;
			}
			lastPos = s.pos + 1;
			s.pos = ((segLen & DNS_SEG_MAX) << 8) | s.data[s.pos];
			continue;
		}

		if (segLen === 0) {
			if (lastPos !== undefined) {
				s.pos = lastPos;
			}
			return res.join('.');
		}

		res.push(bufferToString(s.packet, s.pos + s.offset, segLen));
		s.pos += segLen;
	}

	return null;
}

function makeDNSLabel(str) {
	const spl = str.split('.');
	const data = new Uint8Array(str.length + 2); // First len + 0x00 end
	let pos = 0;
	for (let i = 0; i < spl.length; i++) {
		const s = spl[i];
		data[pos] = s.length;
		stringIntoBuffer(s, data, pos + 1);
		pos += s.length + 1;
	}
	return data;
}

function parseAnswerSection(count, state) {
	const data = state.data;
	const answers = [];

	for (let i = 0; i < count; i++) {
		const a = new DNSAnswer(false);

		a.name = parseDNSLabel(state);
		if (!a.name) {
			return answers;
		}

		a.type = data[state.pos + 1] + (data[state.pos] << 8);
		a.class = data[state.pos + 3] + (data[state.pos + 2] << 8);
		a.ttl = data[state.pos + 7] + (data[state.pos + 6] << 8) + (data[state.pos + 5] << 16) + (data[state.pos + 4] << 24);
		const rdlength = data[state.pos + 9] + (data[state.pos + 8] << 8);
		state.pos += 10;

		a.data = new Uint8Array(state.packet, state.offset + state.pos, rdlength);
		state.pos += rdlength;

		answers.push(a);
	}

	return answers;
}

class DNSPkt extends IHdr {
	fill() {
		this.id = 0;
		this.qr = false;
		this.opcode = 0;
		this.aa = false;
		this.tc = false;
		this.rd = true;
		this.ra = false;
		this.rcode = 0;
		this.questions = []; // QDCOUNT
		this.answers = []; // ANCOUNT
		this.authority = []; // NSCOUNT
		this.additional = []; // ARCOUNT
	}

	static fromPacket(packet, offset) {
		const data = new Uint8Array(packet, offset);
		const bit = new BitArray(packet, offset + 2);

		const dns = new DNSPkt(false);
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
			const q = new DNSQuestion(false);
			q.name = parseDNSLabel(state);
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
			len += (a.name.length + 2) + 10 + a.data.byteLength;
		});
		this.authority.forEach(a => {
			len += (a.name.length + 2) + 10 + a.data.byteLength;
		});
		this.additional.forEach(a => {
			len += (a.name.length + 2) + 10 + a.data.byteLength;
		});
		return len;
	}

	toPacket(array, offset) {
		return this._toPacket(new Uint8Array(array, offset));
	}

	toBytes() {
		const packet = new Uint8Array(this.getFullLength());
		this._toPacket(packet, 0);
		return packet;
	}

	_toPacket(packet) {
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

function makeDNSRequest(domain) {
	const pkt = new DNSPkt();
	const q = new DNSQuestion();
	q.type = DNS_TYPE_A;
	q.name = domain;
	pkt.questions = [q];
	pkt.id = Math.floor(Math.random() * 0xFFFF)
	return makeDNSUDP(pkt);
}

function makeDNSUDP(dns) {
	const pkt = new UDPPkt(false);
	pkt.data = dns.toBytes();
	pkt.sport = 53;
	pkt.dport = 53;
	return pkt;
}

function makeDNSIP() {
	const ip = new IPHdr();
	ip.protocol = PROTO_UDP;
	ip.saddr = ourIp;
	ip.daddr = dnsServerIps[0];
	ip.df = true;
	return ip;
}

udpListen(53, (data, ipHdr) => {
	const dns = DNSPkt.fromPacket(data, 0);
	if (!dns || !dns.qr) {
		return;
	}

	dns.answers.forEach(a => {
		if (a.class !== DNS_CLASS_IN || a.type !== DNS_TYPE_A) {
			return;
		}

		const domain = a.name;
		const ip = IPAddr.fromByteArray(a.data, 0);

		dnsCache[domain] = ip;
		if (dnsQueue[domain]) {
			dnsQueue[domain].forEach(cb => cb(ip));
			delete dnsQueue[domain];
		}
	});
});

function dnsResolve(domain, cb) {
	domain = domain.toLowerCase();

	if (dnsCache[domain]) {
		cb(dnsCache[domain]);
		return;
	}

	if (dnsQueue[domain]) {
		dnsQueue[domain].push(cb);
		return;
	} else {
		dnsQueue[domain] = [cb];
	}

	sendPacket(makeDNSIP(), makeDNSRequest(domain));
}

const IP_REGEX = /^\d+\.\d+\.\d+\.\d+$/;

function dnsResolveOrIp(domain, cb) {
	if (IP_REGEX.test(domain)) {
		cb(IPAddr.fromString(domain));
		return;
	}

	dnsResolve(domain, cb);
}

function dnsTcpConnect(domainOrIp, port, func, cb, dccb) {
	dnsResolveOrIp(domainOrIp, (ip) => {
		tcpConnect(ip, port, func, cb, dccb);
	});
}
