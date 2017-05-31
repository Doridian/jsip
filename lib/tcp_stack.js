'use strict';

const tcpConns = {};
const tcpListeners = {
	7: (data, tcpConn) => { // ECHO
		if (data.byteLength === 1 && (new Uint8Array(data))[0] === 10) {
			tcpConn.close();
		} else {
			tcpConn.send(data);
		}
	},
};

// Public API:
// *connect / *listen / send / close / kill

const TCP_CB_SENT = 0;
const TCP_CB_ACKD = 1;

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

const TCP_ONLY_SEND_ON_PSH = false;

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
		this.wlastsend = 0;
		this.wretrycount = 0;
		this.rlastseqno = undefined;
		this.onack = {};
		this.mss = mtu - 40;
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
			tcp.fillMSS();
		}
		tcp.seqno = this.lseqno;
		if (incSeq) {
			this.incLSeq(1);
		}
		if (this.rseqno !== undefined) {
			tcp.ackno = this.rseqno;
			tcp.setFlag(TCP_ACK);
			this.rlastack = true;
		}
		return tcp;
	}

	delete() {
		this.state = TCP_STATE_CLOSED;
		this.wbuffers = [];
		this.rbuffers = [];
		delete tcpConns[this._id];
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

	addOnAck(cb) {
		if (!cb) {
			return;
		}

		try { cb(TCP_CB_SENT); } catch(e) { }

		const ack = this.lseqno;
		const onack = this.onack[ack];
		if (!onack) {
			this.onack[ack] = [cb];
			return;
		}
		onack.push(cb);
	}

	close(cb) {
		if (!this.wlastack || this.state !== TCP_STATE_ESTABLISHED) {
			this.wbuffers.push({ close: true, cb });
			return;
		}

		const ip = this._makeIp();
		const tcp = this._makeTcp();
		tcp.setFlag(TCP_FIN);
		this.sendPacket(ip, tcp);	
		this.incLSeq(1);

		this.addOnAck(cb);
	}

	sendPacket(ipHdr, tcpPkt) {
		this._lastIp = ipHdr;
		this._lastTcp = tcpPkt;
		sendPacket(ipHdr, tcpPkt);
		this.wlastack = false;
		this.wlastsend = Date.now();
	}

	incRSeq(inc) {
		this.rseqno = (this.rseqno + inc) & 0xFFFFFFFF;
	}

	incLSeq(inc) {
		this.lseqno = (this.lseqno + inc) & 0xFFFFFFFF;
	}

	cycle() {
		if (!this.wlastack && this._lastTcp && this.wlastsend < Date.now() - 1000) {
			if (this.wretrycount > 3) {
				this.kill();
				return;
			}
			sendPacket(this._lastIp, this._lastTcp);
			this.wretrycount++;
		}
	}

	send(data, cb) {
		if (!data || !data.byteLength) {
			return;
		}

		const isReady = this.wlastack && this.state === TCP_STATE_ESTABLISHED;

		if (data.byteLength > this.mss) {
			const first = data.slice(0, this.mss);
			if (!isReady) {
				this.wbuffers.push({ data: first });
			}
			for (let i = this.mss; i < data.byteLength; i += this.mss) {
				this.wbuffers.push({ data: data.slice(i, i + this.mss) });
			}
			if (cb) {
				this.wbuffers[this.wbuffers.length - 1].cb = cb;
			}
			if (!isReady) {
				return;
			}
			data = first;
			cb = undefined;
		}

		if (!isReady) {
			this.wbuffers.push({ data, cb });
			return;
		}

		this._send(data, cb);
	}

	_send(data, cb) {
		const ip = this._makeIp();
		const tcp = this._makeTcp();
		tcp.data = data;
		tcp.setFlag(TCP_PSH);
		this.sendPacket(ip, tcp);
		this.incLSeq(data.byteLength);
		this.addOnAck(cb);
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

		if (this.rlastseqno !== undefined && tcpPkt.seqno <= this.rlastseqno) {
			sendPacket(this.lastack_ip, this.lastack_tcp);
			return;
		}

		if (tcpPkt.hasFlag(TCP_ACK)) {
			if (tcpPkt.ackno === this.lseqno) {
				const onack = this.onack[tcpPkt.ackno];
				if (onack) {
					onack.forEach(cb => { try { cb(TCP_CB_ACKD); } catch(e) { } });
					delete this.onack[tcpPkt.ackno];
				}

				this.wlastack = true;
				this.wretrycount = 0;
				if (this.state === TCP_STATE_CLOSING || this.state === TCP_STATE_LAST_ACK) {
					this.delete();
					return;
				} else if (this.state === TCP_STATE_SYN_SENT) {
					this.state = TCP_STATE_ESTABLISHED;
				}

				const next = this.wbuffers.shift();
				if (next) {
					this._send(next.data, next.cb);
				}
			} else {
				console.log(this.lseqno, tcpPkt);
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
					this.incRSeq(1);
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
					this.incLSeq(1);
					break; 
			}
		}

		if (tcpPkt.hasFlag(TCP_SYN)) {
			this.rlastack = false;
			if (this.state === TCP_STATE_SYN_SENT || this.state === TCP_STATE_SYN_RECEIVED) {
				this.rseqno = tcpPkt.seqno;
				this.incRSeq(1);
				if (this.state === TCP_STATE_SYN_RECEIVED) {
					const ip = this._makeIp();
					const tcp = this._makeTcp();
					this.sendPacket(ip, tcp);			
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
			console.log(this.rseqno, tcpPkt);
			throw new Error('Invalid sequence number');
		}

		if (tcpPkt.data.byteLength > 0) {
			this.rlastseqno = this.rseqno;
			this.rlastack = false;
			this.incRSeq(tcpPkt.data.byteLength);
			const ip = this._makeIp();
			const tcp = this._makeTcp();
			sendPacket(ip, tcp);
			this.lastack_ip = ip;
			this.lastack_tcp = tcp;

			if (TCP_ONLY_SEND_ON_PSH) {
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
			} else {
				this.handler(tcpPkt.data, this);	
			}
		} else if(tcpPkt.flags !== TCP_ACK && !tcpPkt.hasFlag(TCP_FIN)) { // not (only) ACK set?
			this.incRSeq(1);
		}

		if (tcpPkt.mss !== -1) {
			this.mss = tcpPkt.mss;
		}
	}

	accept(ipHdr, tcpPkt) {
		this.state =  TCP_STATE_SYN_RECEIVED;
		this.daddr = ipHdr.saddr;
		this.dport = tcpPkt.sport;
		this.sport = tcpPkt.dport;
		this._id = this.toString();
		tcpConns[this._id] = this;
		this.gotPacket(ipHdr, tcpPkt);
	}

	connect(dport, daddr) {
		this.state = TCP_STATE_SYN_SENT;
		this.daddr = daddr;
		this.dport = dport;
		do {
			this.sport = 4097 + Math.floor(Math.random() * 61347);
			this._id = this.toString();
		} while(tcpConns[this._id] || tcpListeners[this.sport]);
		tcpConns[this._id] = this;

		const ip = this._makeIp();
		const tcp = this._makeTcp();
		this.sendPacket(ip, tcp);
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

function tcpListen(port, func) {
	if (typeof port !== 'number' || port < 1 || port > 65535) {
		return false;
	}

	if  (tcpListeners[port]) {
		return false;
	}

	tcpListeners[port] = func;
	return true;
}

function tcpCloseListener(port) {
	if (typeof port !== 'number' || port < 1 || port > 65535) {
		return false;
	}

	if (port === 7) {
		return false;
	}

	delete tcpListeners[port];
	return true;
}

function tcpConnect(ip, port, func) {
	if (typeof port !== 'number' || port < 1 || port > 65535) {
		return false;
	}

	const conn = new TCPConn(func);
	conn.connect(port, ip);
	return conn;
}

setInterval(1000, () => {
	for (const id in tcpConns) {
		const conn = tcpConns[id];
		conn.cycle();
	}
});