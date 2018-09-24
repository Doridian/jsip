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
}

class DNSAnswer extends IHdr {
	fill() {
		this.name = '';
		this.type = DNS_TYPE_A;
		this.class = DNS_CLASS_IN;
		this.ttl = 0;
		this.data = new Uint8Array(0);
	}
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
		dns.qr = !!bit.read(1);
		dns.opcode = bit.read(4);
		dns.aa = !!bit.read(1);
		dns.tc = !!bit.read(1);
		dns.rd = !!bit.read(1);

		// [3]
		dns.ra = !!bit.read(1);
		bit.skip(3);
		dns.rcode = bit.read(4);

		const qdcount = data[5] + (data[4] << 8);
		const ancount = data[7] + (data[6] << 8);
		const nscount = data[9] + (data[8] << 8);
		const arcount = data[11] + (data[10] << 8);

		return dns;
	}

	getFullLength() {

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
		
	}
}

function makeDNSRequest(domain) {
	const pkt = new DNSPkt();
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
	if (!dns) {
		return;
	}

});

function dnsResolve(domain, cb) {
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