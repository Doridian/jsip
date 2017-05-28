function main() {
	const ws = new WebSocket('wss://tun.doridian.net');
	ws.binaryType = 'arraybuffer';
	window.ws = ws;

	let ourIp, serverIp;

	ws.onmessage = function(msg) {
		const data = msg.data;
		if (typeof data === 'string') {
			const spl = data.split('|');
			ourIp = IPAddr.fromString(spl[1]);
			serverIp = IPAddr.fromString(spl[0]);
			console.log(`Our IP: ${ourIp}`);
			console.log(`Server IP: ${serverIp}`);
		} else {
			const ipHdr = IPHdr.fromPacket(data);
			if (!ipHdr.daddr.equals(ourIp)) {
				console.log('Discarding packet not meant for us');
				return;
			}
			switch (ipHdr.protocol) {
				case 1: // ICMP
					const icmpPkt = ICMPPkt.fromPacket(data, ipHdr.getContentOffset(), ipHdr.getContentLength());
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
					}
			}
		}
	}
}
