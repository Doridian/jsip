'use strict';

function handleEthernet(buffer) {
	let offset = 0;

	const ethHdr = EthHdr.fromPacket(buffer);
	if (!ethHdr) {
		return;
	}

	const isBroadcast = ethHdr.daddr.isBroadcast();

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
			handleIP(buffer, offset);
			break;
		default:
			// We only care about ARP and IPv4
			return;
	}
}
