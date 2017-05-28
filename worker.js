'use strict';

importScripts(
	'lib/util.js',
	'lib/bitfield.js',
	'lib/ip.js',
	'lib/icmp.js'
);

let ourIp, serverIp, mtu, ws;

function sendReply(ipHdr, payload) {
	const fullLength = payload.getFullLength();
	const hdrLen = ipHdr.getContentOffset();
	const mss = mtu - hdrLen;

	if (fullLength <= mss) {
		ipHdr.setContentLength(fullLength);

		const reply = new ArrayBuffer(ipHdr.getFullLength());

		let offset = 0;
		offset += ipHdr.toPacket(reply, offset);
		offset += payload.toPacket(reply, offset);

		ws.send(reply);
	} else if (ipHdr.df) {
		console.log('Needing to send packet too big for MTU/MSS, but DF set');
	} else {
		const pieceMax = Math.ceil(fullLength / mss) - 1;
		ipHdr.mf = true;

		const replyPacket = new ArrayBuffer(fullLength);
		payload.toPacket(replyPacket, 0);
		const r8 = new Uint8Array(replyPacket);

		let pktData = new ArrayBuffer(hdrLen + mss);
		let p8 = new Uint8Array(pktData);

		for (let i = 0; i <= pieceMax; i++) {
			const offset = mss * i;
			let pieceLen = mss;
			if (i === pieceMax) {
				ipHdr.mf = false;
				pieceLen = replyPacket.byteLength % mss;
				pktData = new ArrayBuffer(hdrLen + pieceLen);
				p8 = new Uint8Array(pktData);
			}

			ipHdr.frag_offset = offset >>> 3;
			ipHdr.setContentLength(pieceLen);

			ipHdr.toPacket(pktData, 0);
			for (let j = 0; j < pieceLen; j++) {
				p8[j + hdrLen] = r8[j + offset];
			}

			ws.send(pktData);
		}
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

const fragmentCache = {};

function handleWSData(buffer) {
	const ipHdr = IPHdr.fromPacket(buffer);

	if (!ipHdr.daddr.equals(ourIp)) {
		console.log(`Discarding packet not meant for us, but for ${ipHdr.daddr.toString()}`);
		return;
	}

	const isFrag = ipHdr.mf || ipHdr.frag_offset > 0;
	const pktData = buffer.slice(ipHdr.getContentOffset());

	if (!isFrag) {
		return handlePacket(ipHdr, pktData);
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
			return handlePacket(ipHdr, fullData);
		}
	}
}

function main() {
	ws = new WebSocket('wss://tun.doridian.net');
	ws.binaryType = 'arraybuffer';

	ws.onmessage = function(msg) {
		const data = msg.data;
		if (typeof data === 'string') {
			const spl = data.split('|');
			ourIp = IPAddr.fromString(spl[1]);
			serverIp = IPAddr.fromString(spl[0]);
			mtu = parseInt(spl[2]);
			console.log(`Our IP: ${ourIp}`);
			console.log(`Server IP: ${serverIp}`);
			console.log(`Link-MTU: ${mtu}`);
			mtu -= 4;
			console.log(`TUN-MTU: ${mtu}`);
		} else {
			handleWSData(data);
		}
	}
}

main();
