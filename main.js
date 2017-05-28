function main() {
	const ws = new WebSocket('wss://tun.doridian.net');
	ws.binaryType = 'arraybuffer';
	window.ws = ws;

	let ourIp, serverIp;

	ws.onmessage = function(msg) {
		const data = msg.data;
		console.log(typeof data);
		if (typeof data === 'string') {
			const spl = data.split('|');
			ourIp = IPAddr.fromString(spl[1]);
			serverIp = IPAddr.fromString(spl[0]);
			console.log(`Our IP: ${ourIp}`);
			console.log(`Server IP: ${serverIp}`);
		} else {
			const raw = new Uint8Array(data);
			const ipHdr = IPHdr.fromPacket(raw);
			console.log(ipHdr);
		}
	}
}