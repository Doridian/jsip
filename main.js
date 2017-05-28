let ourIp, serverIp, mtu, ws;

function sendReply(ipHdr, payload) {
	const fullLength = payload.getFullLength();

	if (fullLength + ipHdr.getContentOffset() <= mtu) {
		ipHdr.setContentLength(fullLength);

		const reply = new ArrayBuffer(ipHdr.getFullLength());

		let offset = 0;
		offset += ipHdr.toPacket(reply, offset);
		offset += payload.toPacket(reply, offset);

		ws.send(reply);
	} else {
		console.log('Cannot yet send fragmented reply');
	}
}

function handlePacket(ipHdr, data) {
	switch (ipHdr.protocol) {
		case 1: // ICMP
			const icmpPkt = ICMPPkt.fromPacket(data, 0, data.byteLength);
			switch (icmpPkt.type) {
				case 8: // PING
					const replyIp = new IPHdr();
					replyIp.protocol = 1;
					replyIp.saddr = ourIp;
					replyIp.daddr = ipHdr.saddr;

					const replyICMP = new ICMPPkt();
					replyICMP.type = 0;
					replyICMP.code = 0;
					replyICMP.rest = icmpPkt.rest;
					replyICMP.data = icmpPkt.data;

					sendReply(replyIp, replyICMP);
					break;
				default:
					console.log(`Unhandled ICMP type ${icmpPkt.type}`);
			}
			break;
		case 6: // TCP
			break;
		case 17: // UDP
			break;
		default:
			console.log(`Unhandled IP protocol ${ipHdr.protocol}`);
	}
}

let availableData = 0;
let buffers = [];

const fragmentCache = {};

function pump() {
	while (availableData > 20) {
		const ipHdr = IPHdr.fromPacket(buffers[0]);
		if (availableData < ipHdr.getFullLength()) {
			return;
		}

		const data = new ArrayBuffer(ipHdr.getFullLength());
		const d8 = new Uint8Array(data);
		let left = d8.length;
		let offset = 0;
		while (left > 0) {
			const b = buffers[0];
			const b8 = new Uint8Array(b);
			if (b8.length >= left) {
				for (let i = 0; i < b8.length; i++) {
					d8[offset + i] = b8[i];
				}
				buffers.shift();
				left -= b8.length;
				offset += b8.length;
			} else {
				for (let i = 0; i < left; i++) {
					d8[offset + i] = b8[i];
				}
				buffers[0] = b.slice(left);
				break;
			}
		}

		availableData -= d8.length;

		if (!ipHdr.daddr.equals(ourIp)) {
			console.log(`Discarding packet not meant for us, but for ${ipHdr.daddr.toString()}`);
			return;
		}

		const isFrag = ipHdr.mf || ipHdr.frag_offset > 0;
		const pktData = data.slice(ipHdr.getContentOffset());

		if (!isFrag) {
			return handlePacket(ipHdr, pktData);
		}

		const pktId = ipHdr.id + (ipHdr.saddr.toInt() << 16);
		let curFrag = fragmentCache[pktId];
		if (!curFrag) {
			curFrag = {
				time: Date.getTime(),
			};
			fragmentCache[pktId] = curFrag;
		}

		const fragOffset = ipHdr.frag_offset << 3;
		curFrag[fragOffset] = {
			ipHdr,
			pktData,
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
				curPiecePos += curPiece.pktData.byteLength;
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
				const fullData = new ArrayBuffer(curFrag[curFrag.last].pktData.byteLength + curFrag.last);
				const d8 = new Uint8Array(fullData);
				let curPiecePos = 0;
				let curPiece = curFrag[curPiecePos];
				while (true) {
					const p8 = new Uint8Array(curPiece.pktData);
					for (let i = 0; i < p8.length; i++) {
						d8[curPiecePos + i] = p8[i];
					}
					if (!curPiece.ipHdr.mf) {
						break;
					}
					curPiecePos += curPiece.pktData.byteLength;
					curPiece = curFrag[curPiecePos];
				}
				console.log(d8);
				return handlePacket(ipHdr, fullData);
			}
		}
	}
}

function main() {
	ws = new WebSocket('wss://tun.doridian.net');
	ws.binaryType = 'arraybuffer';
	window.ws = ws;

	ws.onmessage = function(msg) {
		const data = msg.data;
		if (typeof data === 'string') {
			const spl = data.split('|');
			ourIp = IPAddr.fromString(spl[1]);
			serverIp = IPAddr.fromString(spl[0]);
			mtu = parseInt(spl[2]);
			console.log(`Our IP: ${ourIp}`);
			console.log(`Server IP: ${serverIp}`);
			console.log(`MTU: ${mtu}`)
		} else {
			buffers.push(data);
			availableData += data.byteLength;
			pump();
		}
	}
}
