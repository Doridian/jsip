'use strict';

let ourIp, serverIp, ourSubnet, gatewayIp, ourMac, mtu, mss, ws, sendEth, ethBcastHdr, dnsServerIps;

try {
	importScripts(
		'lib/util.js',
		'lib/bitfield.js',
		'lib/ethernet.js',
		'lib/ip.js',
		'lib/arp.js',
		'lib/icmp.js',
		'lib/udp.js',
		'lib/tcp.js',
		'lib/tcp_stack.js',
		'lib/udp_stack.js',
		'lib/dhcp.js',
		'lib/dns.js',
		'lib/http.js',
	);
} catch(e) { }

const arpCache = {
	[IP_BROADCAST.toString()]: MAC_BROADCAST,
};
const arpQueue = {};
const arpTimeouts = {};
let ipDoneCB = null;

function makeEthIPHdr(destIp, cb) {
	if (ourSubnet && !ourSubnet.contains(destIp)) {
		destIp = gatewayIp;
	}

	const destIpStr = destIp.toString();

	const ethHdr = new EthHdr(false);
	ethHdr.ethtype = ETH_IP;
	ethHdr.saddr = ourMac;
	if (arpCache[destIpStr]) {
		ethHdr.daddr = arpCache[destIpStr];
		cb(ethHdr);
		return;
	}

	const _cb = (addr) => {
		ethHdr.daddr = addr;
		cb(ethHdr);
	};

	if (arpQueue[destIpStr]) {
		arpQueue[destIpStr].push(_cb);
		return;
	}

	arpQueue[destIpStr] = [_cb];
	arpTimeouts[destIpStr] = setTimeout(() => {
		delete arpTimeouts[destIpStr];
		if (arpQueue[destIpStr]) {
			arpQueue[destIpStr].forEach(cb => cb(null));
			delete arpQueue[destIpStr];
		}
	}, 10000);

	const arpReq = new ARPPkt();
	arpReq.operation = ARP_REQUEST;
	arpReq.sha = ourMac;
	arpReq.spa = ourIp;
	arpReq.tha = MAC_BROADCAST;
	arpReq.tpa = destIp;
	sendARPPkt(arpReq);
}

function sendPacket(ipHdr, payload) {
	if (!sendEth) {
		_sendPacket(ipHdr, payload);
		return;
	}
	makeEthIPHdr(ipHdr.daddr, (ethHdr) => {
		if (!ethHdr) {
			return;
		}
		_sendPacket(ipHdr, payload, ethHdr);
	});
}

function _sendPacket(ipHdr, payload, ethIPHdr) {
	const fullLength = payload.getFullLength(); 
	const hdrLen = (ethIPHdr ? ETH_LEN : 0) + ipHdr.getContentOffset();
	const _mss = mtu - hdrLen;

	if (fullLength <= _mss) {
		ipHdr.setContentLength(fullLength);

		const reply = new ArrayBuffer((ethIPHdr ? ETH_LEN : 0) + ipHdr.getFullLength());

		let offset = 0;
		if (ethIPHdr) {
			offset += ethIPHdr.toPacket(reply, offset);
		}
		offset += ipHdr.toPacket(reply, offset, ipHdr);
		offset += payload.toPacket(reply, offset, ipHdr);

		ws.send(reply);
	} else if (ipHdr.df) {
		throw new Error('Needing to send packet too big for MTU/MSS, but DF set');
	} else {
		const pieceMax = Math.ceil(fullLength / _mss) - 1;
		ipHdr.mf = true;

		const replyPacket = new ArrayBuffer(fullLength);
		payload.toPacket(replyPacket, 0, ipHdr);
		const r8 = new Uint8Array(replyPacket);

		let pktData = new ArrayBuffer(hdrLen + _mss);
		let p8 = new Uint8Array(pktData);

		for (let i = 0; i <= pieceMax; i++) {
			const offset = _mss * i;
			let pieceLen = _mss;
			if (i === pieceMax) {
				ipHdr.mf = false;
				pieceLen = replyPacket.byteLength % _mss;
				pktData = new ArrayBuffer(hdrLen + pieceLen);
				p8 = new Uint8Array(pktData);
			}

			console.log(offset, pieceLen, fullLength);

			ipHdr.frag_offset = offset >>> 3;
			ipHdr.setContentLength(pieceLen);

			if (ethIPHdr) {
				ethIPHdr.toPacket(pktData, 0);
				ipHdr.toPacket(pktData, ETH_LEN, ipHdr);
			} else {
				ipHdr.toPacket(pktData, 0, ipHdr);
			}
			for (let j = 0; j < pieceLen; j++) {
				p8[j + hdrLen] = r8[j + offset];
			}

			ws.send(pktData);
		}
	}
}

function handlePacket(ipHdr, data, offset) {
	const len = data.byteLength - offset;

	switch (ipHdr.protocol) {
		case PROTO_ICMP:
			const icmpPkt = ICMPPkt.fromPacket(data, offset, len);
			switch (icmpPkt.type) {
				case 8: // PING / Echo Request
					const replyIp = ipHdr.makeReply();

					const replyICMP = new ICMPPkt();
					replyICMP.type = 0;
					replyICMP.code = 0;
					replyICMP.rest = icmpPkt.rest;
					replyICMP.data = icmpPkt.data;

					sendPacket(replyIp, replyICMP);
					break;
				default:
					console.log(`Unhandled ICMP type ${icmpPkt.type}`);
					break;
			}
			break;
		case PROTO_TCP: // TCP
			const tcpPkt = TCPPkt.fromPacket(data, offset, len, ipHdr);
			tcpGotPacket(ipHdr, tcpPkt);
			break;
		case PROTO_UDP: // UDP
			const udpPkt = UDPPkt.fromPacket(data, offset, len, ipHdr);
			udpGotPacket(ipHdr, udpPkt);
			break;
		default:
			console.log(`Unhandled IP protocol ${ipHdr.protocol}`);
			break;
	}
}

const fragmentCache = {};

function sendARPPkt(arpPkt, fromAddr) {
	const pkt = new ArrayBuffer(ETH_LEN + ARP_LEN);

	const ethHdr = new EthHdr(false);
	ethHdr.daddr = fromAddr || MAC_BROADCAST;
	ethHdr.saddr = ourMac;
	ethHdr.ethtype = ETH_ARP;

	ethHdr.toPacket(pkt, 0);
	arpPkt.toPacket(pkt, ETH_LEN);

	ws.send(pkt);
}

function handleARP(ethHdr, buffer, offset) {
	const arpPkt = ARPPkt.fromPacket(buffer, offset);
	switch (arpPkt.operation) {
		case ARP_REQUEST:
			if (arpPkt.tpa.equals(ourIp)) {
				const arpReply = arpPkt.makeReply();
				sendARPPkt(arpReply, ethHdr.saddr);
			}
			break;
		case ARP_REPLY:
			const ip = arpPkt.spa;
			const mac = arpPkt.sha;
			arpCache[ip] = mac;
			if (arpQueue[ip]) {
				arpQueue[ip].forEach(cb => cb(mac));
				delete arpQueue[ip];
			}
			if (arpTimeouts[ip]) {
				clearTimeout(arpTimeouts[ip]);
				delete arpTimeouts[ip];
			}
			break;
	}
}

function handleIP(buffer) {
	let offset = 0;
	if (sendEth) {
		const ethHdr = EthHdr.fromPacket(buffer);
		if (!ethHdr) {
			return;
		}

		const isBroadcast = ethHdr.daddr.equals(MAC_BROADCAST);

		if (!ethHdr.daddr.equals(ourMac) && !isBroadcast) {
			console.log(`Discarding packet not meant for us, but for ${ethHdr.daddr.toString()}`);
			return;
		}

		offset += ethHdr.getContentOffset();

		switch (ethHdr.ethtype) {
			case ETH_ARP:
				handleARP(ethHdr, buffer, offset);
				return;
			case ETH_IP:
				// Fall through to the normal handling
				break;
			default:
				// We only care about ARP and IPv4
				return;
		}
	}

	const ipHdr = IPHdr.fromPacket(buffer, offset);
	if (!ipHdr) {
		return;
	}

	if (ipHdr.daddr.equals(IP_BROADCAST)) {
		ipHdr.daddr = ourIp;
	}

	if (ourIp && !ipHdr.daddr.equals(ourIp)) {
		console.log(`Discarding packet not meant for us, but for ${ipHdr.daddr.toString()}`);
		return;
	}

	const isFrag = ipHdr.mf || ipHdr.frag_offset > 0;
	offset += ipHdr.getContentOffset();
	//const pktData = buffer.slice(ipHdr.getContentOffset());

	if (!isFrag) {
		return handlePacket(ipHdr, buffer, offset);
	}

	const pktId = ipHdr.id + (ipHdr.saddr.toInt() << 16);
	let curFrag = fragmentCache[pktId];
	if (!curFrag) {
		curFrag = {
			time: Date.now(),
		};
		fragmentCache[pktId] = curFrag;
	}

	const fragOffset = ipHdr.frag_offset << 3;
	curFrag[fragOffset] = {
		ipHdr,
		buffer,
		offset,
		len: buffer.byteLength - offset,
	};
	if (!ipHdr.mf) {
		curFrag.last = fragOffset;
	}
	if (ipHdr.frag_offset === 0) {
		curFrag.validUntil = 0;
	}

	// Check if we got all fragments
	if (curFrag.validUntil !== undefined && curFrag.last !== undefined) {
		let curPiecePos = curFrag.validUntil;
		let curPiece = curFrag[curPiecePos];
		let gotAll = false;
		while (true) {
			curPiecePos += curPiece.len;
			curPiece = curFrag[curPiecePos];
			if (!curPiece) {
				break;
			}
			if (!curPiece.ipHdr.mf) {
				gotAll = true;
				break;
			}
		}

		if (gotAll) {
			const fullData = new ArrayBuffer(curFrag[curFrag.last].len + curFrag.last);
			const d8 = new Uint8Array(fullData);
			let curPiecePos = 0;
			let curPiece = curFrag[curPiecePos];
			while (true) {
				const p8 = new Uint8Array(curPiece.buffer, curPiece.offset);
				for (let i = 0; i < p8.length; i++) {
					d8[curPiecePos + i] = p8[i];
				}
				if (!curPiece.ipHdr.mf) {
					break;
				}
				curPiecePos += curPiece.len;
				curPiece = curFrag[curPiecePos];
			}
			return handlePacket(ipHdr, fullData);
		}
	}
}

function timeoutFragments() {
	const cutoff = Date.now() - 30000;
	for (let id in fragmentCache) {
		const frag = fragmentCache[id];
		if (frag.time < cutoff) {
			delete fragmentCache[id];
		}
	}
}

function workerMain(cb) {
	const proto = (document.location.protocol === 'http:') ? 'ws:' : 'wss:';
	_workerMain(`${proto}//doridian.net/ws`, cb);
}

function configOut() {
	console.log(`Our Subnet: ${ourSubnet}`);
	console.log(`Our IP: ${ourIp}`);
	console.log(`Server IP: ${serverIp}`);
	console.log(`Gateway IP: ${gatewayIp}`);
}

function handleInit(data, cb) {
	let needDHCP = false;
	// 1|init|TUN|192.168.3.1/24|1280
	const spl = data.split('|');

	switch (spl[2]) {
		case 'TAP':
			sendEth = true;
		case 'TUN':
			ourSubnet = IPNet.fromString(spl[3]);
			serverIp = ourSubnet.getAddress(0);
			break;
		case 'TAP_NOCONF':
			sendEth = true;
			ourSubnet = null;
			serverIp = null;
			needDHCP = true;
			break;
	}

	mtu = parseInt(spl[4], 10);

	console.log(`Mode: ${spl[2]}`);

	console.log(`Link-MTU: ${mtu}`);
	mtu -= 4;
	console.log(`TUN-MTU: ${mtu}`);

	mss = mtu - 40;

	if (sendEth) {
		mss -= ETH_LEN;

		ourMac = MACAddr.fromBytes(0x0A, randomByte(), randomByte(), randomByte(), randomByte(), randomByte());
		console.log(`Our MAC: ${ourMac}`);
		ethBcastHdr = new EthHdr();
		ethBcastHdr.ethtype = ETH_IP;
		ethBcastHdr.saddr = ourMac;
		ethBcastHdr.daddr = MAC_BROADCAST;
	}

	if (ourSubnet) {
		ourIp = ourSubnet.ip;
	} else {
		ourIp = null;
	}
	gatewayIp = serverIp;
	dnsServerIps = [gatewayIp];
	configOut();

	if (needDHCP) {
		console.log('Starting DHCP procedure...');
		ipDoneCB = cb;
		dhcpNegotiate();
	} else if (cb) {
		setTimeout(cb, 0);
	}
}

function _workerMain(url, cb) {
	console.log(`Connecting to WSVPN: ${url}`);

	ws = new WebSocket(url);
	ws.binaryType = 'arraybuffer';

	ws.onmessage = function(msg) {
		const data = msg.data;
		if (typeof data !== 'string') {
			handleIP(data);
			return;
		}

		handleInit(data, cb);
	}
}

onmessage = function (e) {
	const cmd = e.data[0];
	const _id = e.data[1];
	switch (e.data[0]) {
		case 'connect':
			_workerMain(e.data[2], () => {
				postMessage(['connect', _id, ourIp, serverIp, gatewayIp, ourSubnet, mtu]);
			});
			break;
		case 'httpGet':
			httpGet(e.data[2], (err, res) => {
				postMessage(['httpGet', _id, err, res]);
			});
			break;
	}
};

setInterval(timeoutFragments, 1000);
