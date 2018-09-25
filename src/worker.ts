import { config, configOut } from "./config";
import { IPNet } from "./ip";
import { MACAddr, EthHdr, ETH_TYPE, MAC_BROADCAST } from "./ethernet";
import { randomByte } from "./util";
import { dhcpNegotiate } from "./dhcp";
import { handleEthernet } from "./ethernet_stack";
import { handleIP } from "./ip_stack";
import { httpGet } from "./http";

type VoidCB = () => void;

export function workerMain(cb: VoidCB) {
	const proto = (document.location.protocol === 'http:') ? 'ws:' : 'wss:';
	_workerMain(`${proto}//doridian.net/ws`, cb);
}

function handleInit(data: string, cb: VoidCB) {
	let needDHCP = false;
	// 1|init|TUN|192.168.3.1/24|1280
	const spl = data.split('|');

	switch (spl[2]) {
		case 'TAP':
			config.sendEth = true;
		case 'TUN':
			config.ourSubnet = IPNet.fromString(spl[3]);
			config.serverIp = config.ourSubnet.getAddress(0);
			break;
		case 'TAP_NOCONF':
			config.sendEth = true;
			config.ourSubnet = undefined;
			config.serverIp = undefined;
			needDHCP = true;
			break;
	}

	config.mtu = parseInt(spl[4], 10);

	console.log(`Mode: ${spl[2]}`);

	console.log(`Link-MTU: ${config.mtu}`);

	config.mss = config.mtu - 40;

	if (config.sendEth) {
		config.ourMac = MACAddr.fromBytes(0x0A, randomByte(), randomByte(), randomByte(), randomByte(), randomByte());
		console.log(`Our MAC: ${config.ourMac}`);
		config.ethBcastHdr = new EthHdr();
		config.ethBcastHdr.ethtype = ETH_TYPE.IP;
		config.ethBcastHdr.saddr = config.ourMac;
		config.ethBcastHdr.daddr = MAC_BROADCAST;
	}

	if (config.ourSubnet) {
		config.ourIp = config.ourSubnet.ip;
	} else {
		config.ourIp = undefined;
	}
	config.gatewayIp = config.serverIp;
	config.dnsServerIps = [config.gatewayIp!];
	configOut();

	if (needDHCP) {
		console.log('Starting DHCP procedure...');
		config.ipDoneCB = cb;
		dhcpNegotiate();
	} else if (cb) {
		setTimeout(cb, 0);
	}
}

function _workerMain(url: string, cb: VoidCB) {
	console.log(`Connecting to WSVPN: ${url}`);

	config.ws = new WebSocket(url);
	config.ws.binaryType = 'arraybuffer';

	config.ws.onmessage = function(msg) {
		const data = msg.data;
		if (typeof data !== 'string') {
			if (config.sendEth) {
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
	switch (cmd) {
		case 'connect':
			_workerMain(e.data[2], () => {
				postMessage(['connect', _id, config.ourIp, config.serverIp, config.gatewayIp, config.ourSubnet, config.mtu], "");
			});
			break;
		case 'httpGet':
			httpGet(e.data[2], (err, res) => {
				postMessage(['httpGet', _id, err, res], "");
			});
			break;
	}
};

