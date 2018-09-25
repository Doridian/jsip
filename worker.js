'use strict';

let ourIp, serverIp, ourSubnet, gatewayIp, ourMac, mtu, mss, ws, sendEth, ethBcastHdr, dnsServerIps;

try {
	importScripts(
		'lib/util.js',
		'lib/bitfield.js',
		'lib/ethernet.js',
		'lib/ethernet_stack.js',
		'lib/ip.js',
		'lib/ip_stack.js',
		'lib/arp.js',
		'lib/arp_stack.js',
		'lib/icmp.js',
		'lib/icmp_stack.js',
		'lib/udp.js',
		'lib/udp_stack.js',
		'lib/tcp.js',
		'lib/tcp_stack.js',
		'lib/dhcp.js',
		'lib/dns.js',
		'lib/http.js',
	);
} catch(e) { }

let ipDoneCB = null;

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
	const _cOffset = ipHdr.getContentOffset();
	const hdrLen = (ethIPHdr ? ETH_LEN : 0) + _cOffset;
	const _mss = mtu - _cOffset;

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
		const __mss = (_mss >>> 3) << 3;

		const pieceMax = Math.ceil(fullLength / __mss) - 1;
		ipHdr.mf = true;

		const replyPacket = new ArrayBuffer(fullLength);
		payload.toPacket(replyPacket, 0, ipHdr);
		const r8 = new Uint8Array(replyPacket);

		let pktData = new ArrayBuffer(hdrLen + __mss);
		let p8 = new Uint8Array(pktData);

		for (let i = 0; i <= pieceMax; i++) {
			const offset = __mss * i;
			let pieceLen = __mss;
			if (i === pieceMax) {
				ipHdr.mf = false;
				pieceLen = replyPacket.byteLength % __mss;
				pktData = new ArrayBuffer(hdrLen + pieceLen);
				p8 = new Uint8Array(pktData);
			}

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

	mss = mtu - 40;

	if (sendEth) {
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
			if (sendEth) {
				handleEthernet(data);
			} else {
				handleIP(data);
			}
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
