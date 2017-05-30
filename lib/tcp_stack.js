'use strict';

const tcpConns = {};
const tcpListeners = {
	7: (data, tcpConn) => { // ECHO
		tcpConn.send(data);
	},
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
	constructor(handler) {
		this.handler = handler;
		this.state = TCP_STATE_CLOSED;
		this.daddr = null;
		this.sport = 0;
		this.dport = 0;
		this.lseqno = undefined;
		this.rseqno = undefined;
		this.wnd = 65535;
		this.lastack = undefined;
		this.wbuffers = [];
		this.rbuffers = [];
		this.rbufferlen = 0;
		this.rlastack = false;
		this.wlastack = false;
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
		let incSeq = false;
		if (this.lseqno === undefined) {
			this.lseqno = Math.floor(Math.random() * (1 << 30));
			tcp.setFlag(TCP_SYN);
			incSeq = true;
		}
		tcp.seqno = this.lseqno;
		if (incSeq) {
			this.lseqno = (this.lseqno + 1) & 0xFFFFFFFF;
		}
		if (this.rseqno !== undefined) {
			tcp.ackno = this.rseqno;
			tcp.setFlag(TCP_ACK);
			this.rlastack = true;
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

	delete() {
		this.state = TCP_STATE_CLOSED;
		this.wbuffers = [];
		this.rbuffers = [];
		delete tcpConns[this.toString()];
	}

	kill() {
		const ip = this._makeIp();
		const tcp = this._makeTcp();
		tcp.ack = 0;
		tcp.flags = 0;
		tcp.setFlag(TCP_RST);
		sendPacket(ip, tcp);
		this.delete();
	}

	close() {

	}

	send(data) {
		if (!data || !data.byteLength) {
			return;
		}

		if (!this.wlastack || this.state !== TCP_STATE_ESTABLISHED) {
			this.wbuffers.push(data);
			return;
		}

		const ip = this._makeIp();
		const tcp = this._makeTcp(false);
		tcp.data = data;
		tcp.setFlag(TCP_PSH);
		sendPacket(ip, tcp);
		this.lseqno = (this.lseqno + data.byteLength) & 0xFFFFFFFF;
		this.wlastack = false;
	}

	gotPacket(ipHdr, tcpPkt) {
		if (this.state === TCP_STATE_CLOSED) {
			return this.kill();
		}

		if (tcpPkt.hasFlag(TCP_RST)) {
			this.rlastack = false;
			this.delete();
			return;
		}

		if (tcpPkt.hasFlag(TCP_ACK)) {
			if (tcpPkt.ackno === this.lseqno) {
				this.wlastack = true;
				if (this.state === TCP_STATE_CLOSING || this.state === TCP_STATE_LAST_ACK) {
					this.delete();
					return;
				} else if (this.state === TCP_STATE_SYN_SENT) {
					this.state = TCP_STATE_ESTABLISHED;
				}
				this.send(this.wbuffers.shift());
			} else {
				throw new Error('Wrong ACK');
			}
		}

		if (tcpPkt.hasFlag(TCP_FIN)) {
			this.rlastack = false;
			const ip = this._makeIp();
			const tcp = this._makeTcp();
			switch (this.state) {
				case TCP_STATE_FIN_WAIT_1:
				case TCP_STATE_FIN_WAIT_2:
					sendPacket(ip, tcp); // ACK it
					if (!tcpPkt.hasFlag(TCP_ACK)) {
						this.state == TCP_STATE_CLOSING;
					} else {
						this.delete();
					}
					break;
				case TCP_STATE_CLOSING:
					break;
				default:
					this.state = TCP_STATE_LAST_ACK;
					tcp.setFlag(TCP_FIN);
					sendPacket(ip, tcp);
					break; 
			}
		}

		if (tcpPkt.hasFlag(TCP_SYN)) {
			this.rlastack = false;
			if (this.state === TCP_STATE_SYN_SENT || this.state === TCP_STATE_SYN_RECEIVED) {
				this.rseqno = (tcpPkt.seqno + 1) & 0xFFFFFFFF;
				if (this.state === TCP_STATE_SYN_RECEIVED) {
					const ip = this._makeIp();
					const tcp = this._makeTcp();
					sendPacket(ip, tcp);				
				}
				this.state = TCP_STATE_ESTABLISHED;
			} else {
				throw new Error('Unexpected SYN');
			}
			return;
		}

		if (this.rseqno === undefined) {
			console.log('Wanted SYN, but got none');
			return;
		}

		if (tcpPkt.seqno !== this.rseqno) {
			throw new Error('Invalid sequence number');
		}

		if (tcpPkt.data.byteLength > 0) {
			this.rlastack = false;
			this.rseqno = (tcpPkt.seqno + tcpPkt.data.byteLength) & 0xFFFFFFFF;
			const ip = this._makeIp();
			const tcp = this._makeTcp();
			sendPacket(ip, tcp);

			this.rbufferlen += tcpPkt.data.byteLength;
			this.rbuffers.push(tcpPkt.data);

			if (tcpPkt.hasFlag(TCP_PSH)) {
				const all = new ArrayBuffer(this.rbufferlen);
				const a8 = new Uint8Array(all);
				let pos = 0;
				for (let i = 0; i < this.rbuffers.length; i++) {
					const b8 = new Uint8Array(this.rbuffers[i]);
					for (let j = 0; j < b8.length; j++) {
						a8[pos + j] = b8[j];
					}
					pos += b8.length;
				}
				this.rbuffers = [];
				this.handler(all, this);
			}
		}
	}

	accept(ipHdr, tcpPkt) {
		this.state =  TCP_STATE_SYN_RECEIVED;
		this.daddr = ipHdr.saddr;
		this.dport = tcpPkt.sport;
		this.sport = tcpPkt.dport;
		tcpConns[this.toString()] = this; 
		this.gotPacket(ipHdr, tcpPkt);
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
		const conn = new TCPConn(tcpListeners[tcpPkt.dport]);
		return conn.accept(ipHdr, tcpPkt);
	}
}
