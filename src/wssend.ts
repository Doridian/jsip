import { IPHdr } from "./ip";
import { IPacket } from "./util";
import { EthHdr, ETH_LEN } from "./ethernet";
import { config } from "./config";
import { makeEthIPHdr } from "./arp_stack";

export function sendPacket(ipHdr: IPHdr, payload: IPacket) {
    if (!ipHdr) {
        return;
    }

    if (!config.sendEth) {
		_sendPacket(ipHdr, payload);
		return;
	}
	makeEthIPHdr(ipHdr.daddr!, (ethHdr) => {
		if (!ethHdr) {
			return;
		}
		_sendPacket(ipHdr, payload, ethHdr);
	});
}

function _sendPacket(ipHdr: IPHdr, payload: IPacket, ethIPHdr?: EthHdr) {
	const fullLength = payload.getFullLength(); 
	const _cOffset = ipHdr.getContentOffset();
	const hdrLen = (ethIPHdr ? ETH_LEN : 0) + _cOffset;
	const _mss = config.mtu - _cOffset;

	if (fullLength <= _mss) {
		ipHdr.setContentLength(fullLength);

		const reply = new ArrayBuffer((ethIPHdr ? ETH_LEN : 0) + ipHdr.getFullLength());

		let offset = 0;
		if (ethIPHdr) {
			offset += ethIPHdr.toPacket(reply, offset);
		}
		offset += ipHdr.toPacket(reply, offset);
		offset += payload.toPacket(reply, offset, ipHdr);

		config.ws!.send(reply);
	} else if (ipHdr.df) {
		throw new Error("Needing to send packet too big for MTU/MSS, but DF set");
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
				ipHdr.toPacket(pktData, ETH_LEN);
			} else {
				ipHdr.toPacket(pktData, 0);
			}
			for (let j = 0; j < pieceLen; j++) {
				p8[j + hdrLen] = r8[j + offset];
			}

			config.ws!.send(pktData);
		}
	}
}
