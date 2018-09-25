'use strict';

const ethHandlers = {};

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

	const handler = ethHandlers[ethHdr.ethtype];
	if (handler) {
		handler(buffer, offset, ethHdr);
	}
}

function registerEthHandler(ethtype, handler) {
	ethHandlers[ethtype] = handler;
}
