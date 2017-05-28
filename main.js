let ourIp, serverIp, ws;

function handlePacket(ipHdr, data) {
	switch (ipHdr.protocol) {
		case 1: // ICMP
			const icmpPkt = ICMPPkt.fromPacket(data, 0, data.byteLength);
			switch (icmpPkt.type) {
				case 8: // PING
					let offset = 0;
					const replyIp = new IPHdr();
					replyIp.df = true;
					replyIp.protocol = 1;
					replyIp.saddr = ourIp;
					replyIp.daddr = ipHdr.saddr;

					const replyICMP = new ICMPPkt();
					replyICMP.type = 0;
					replyICMP.code = 0;
					replyICMP.rest = icmpPkt.rest;
					replyICMP.data = icmpPkt.data;

					replyIp.setContentLength(icmpPkt.getFullLength());

					const reply = new ArrayBuffer(replyIp.getFullLength());

					offset += replyIp.toPacket(reply, offset);
					offset += replyICMP.toPacket(reply, offset);

					ws.send(reply);
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

		if (ipHdr.mf || ipHdr.frag_offset > 0) {
			console.log(`Discarding packet that has fragmentation`);
			return;
		}

		const pktData = data.slice(ipHdr.getContentOffset());

		handlePacket(ipHdr, pktData);
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
			console.log(`Our IP: ${ourIp}`);
			console.log(`Server IP: ${serverIp}`);
		} else {
			buffers.push(data);
			availableData += data.byteLength;
			pump();
		}
	}
}
