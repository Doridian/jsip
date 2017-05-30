'use strict';

const tcpConns = {};
const tcpListeners = {
	80: 'dummy',
};

const TCP_STATE_CLOSED = 0;
const TCP_STATE_SYN_SENT = 1;
const TCP_STATE_SYN_RECEIVED = 2;
const TCP_STATE_FIN_WAIT_1 = 3;
const TCP_STATE_FIN_WAIT_2 = 4;
const TCP_STATE_CLOSING = 5;
const TCP_STATE_TIME_WAIT = 6;
const TCP_STATE_CLOSE_WAIT = 7;
const TCP_STATE_LAST_ACK = 8;
const TCP_STATE_ESTABLISHED = 9;

class TCPConn {
	constructor() {
		this.state = TCP_STATE_CLOSED;
		this.daddr = null;
		this.sport = 0;
		this.dport = 0;
		this.lseqno = undefined;
		this.rseqno = undefined;
		this.wnd = 65535;
	}

	_makeIp() {
		const ip = new IPHdr();
		ip.protocol = PROTO_TCP;
		ip.saddr = ourIp;
		ip.daddr = this.daddr;
		return ip;		
	}

	_makeTcp() {
		const tcp = new TCPPkt();
		tcp.window_size = this.wnd;
		tcp.dport = this.dport;
		tcp.sport = this.sport;
		if (this.lseqno === undefined) {
			this.lseqno = Math.floor(Math.random() * (1 << 30));
			tcp.setFlag(TCP_SYN);
		}
		tcp.seqno = this.lseqno++;
		this.lseqno &= 0xFFFFFFFF;
		if (this.rseqno !== undefined) {
			tcp.ackno = this.rseqno;
			tcp.setFlag(TCP_ACK);
		}
		return tcp;
	}

	connect(dport, daddr) {
		this.state = TCP_STATE_SYN_SENT;
		this.daddr = daddr;
		this.dport = dport;
		do {
			this.sport = 4097 + Math.floor(Math.random() * 61347);
		} while(tcpConns[this.toString()]);
		tcpConns[this.toString()] = this;

		const ip = this._makeIp();
		const tcp = this._makeTcp();
		sendPacket(ip, tcp);
	}

	gotPacket(ipHdr, tcpPkt) {
		if (tcpPkt.hasFlag(TCP_SYN)) {
			if (this.state === TCP_STATE_SYN_SENT || this.state === TCP_STATE_SYN_RECEIVED) {
				this.rseqno = (tcpPkt.seqno + 1) & 0xFFFFFFFF;
				if (this.state === TCP_STATE_SYN_RECEIVED) {
					const ip = this._makeIp();
					const tcp = this._makeTcp();
					sendPacket(ip, tcp);				
				}
				this.state = TCP_STATE_ESTABLISHED;
			} else {
				console.log('No SYN expected');
			}
			return;
		}

		if (this.rseqno === undefined) {
			console.log('Wanted SYN...');
			return;
		}

		if (tcpPkt.seqno !== this.rseqno) {
			throw new Error('Invalid sequence number');
		}

		this.rseqno = (tcpPkt.seqno + tcpPkt.data.byteLength) & 0xFFFFFFFF;

		if (tcpPkt.data.byteLength > 0) {
			const ip = this._makeIp();
			const tcp = this._makeTcp();
			sendPacket(ip, tcp);
		}

		return tcpPkt.data;
	}

	accept(ipHdr, tcpPkt) {
		this.state =  TCP_STATE_SYN_RECEIVED;
		this.daddr = ipHdr.saddr;
		this.dport = tcpPkt.sport;
		this.sport = tcpPkt.dport;
		tcpConns[this.toString()] = this;
		return this.gotPacket(ipHdr, tcpPkt);
	}

	toString() {
		return `${this.daddr}|${this.sport}|${this.dport}`;
	}
}

function tcpGotPacket(ipHdr, tcpPkt) {
	const id = `${ipHdr.saddr}|${tcpPkt.dport}|${tcpPkt.sport}`;
	if (tcpConns[id]) {
		return tcpConns[id].gotPacket(ipHdr, tcpPkt);
	}

	if (tcpPkt.hasFlag(TCP_SYN) && !tcpPkt.hasFlag(TCP_ACK) && tcpListeners[tcpPkt.dport]) {
		const conn = new TCPConn();
		return conn.accept(ipHdr, tcpPkt);
	}
}
