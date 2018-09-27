import { config } from "../../config";
import { IPacket } from "../../ipacket";
import { handlePacket } from "../../util/packet";
import { sendRaw } from "../../wsvpn";
import { makeEthIPHdr } from "../arp/stack";
import { ETH_LEN, EthHdr } from "../index";
import { IPHdr } from "./index";

export function sendIPPacket(ipHdr: IPHdr, payload: IPacket) {
    if (!config.enableEthernet) {
        _sendIPPacket(ipHdr, payload);
        return;
    }

    makeEthIPHdr(ipHdr.daddr, (ethHdr) => {
        if (!ethHdr) {
            return;
        }
        _sendIPPacket(ipHdr, payload, ethHdr);
    });
}

function _sendIPPacket(ipHdr: IPHdr, payload: IPacket, ethIPHdr?: EthHdr) {
    const fullLength = payload.getFullLength();
    const cOffset = ipHdr.getContentOffset();
    const hdrLen = (ethIPHdr ? ETH_LEN : 0) + cOffset;
    const maxPacketSize = config.mtu - cOffset;

    const isLoopback = ipHdr.daddr.isLoopback();

    if (fullLength <= maxPacketSize) {
        ipHdr.setContentLength(fullLength);

        const reply = new ArrayBuffer((ethIPHdr ? ETH_LEN : 0) + ipHdr.getFullLength());

        let offset = 0;
        if (ethIPHdr) {
            offset += ethIPHdr.toPacket(reply, offset);
        }
        offset += ipHdr.toPacket(reply, offset);
        offset += payload.toPacket(reply, offset, ipHdr);

        if (isLoopback) {
            handlePacket(reply);
        } else {
            sendRaw(reply);
        }
        return;
    }

    if (ipHdr.df) {
        throw new Error("Needing to send packet too big for MTU/MSS, but DF set");
    }

    const maxPacketSizeFrag = (maxPacketSize >>> 3) << 3;

    const pieceMax = Math.ceil(fullLength / maxPacketSizeFrag) - 1;
    ipHdr.mf = true;

    const replyPacket = new ArrayBuffer(fullLength);
    payload.toPacket(replyPacket, 0, ipHdr);
    const r8 = new Uint8Array(replyPacket);

    let pktData = new ArrayBuffer(hdrLen + maxPacketSizeFrag);
    let p8 = new Uint8Array(pktData);

    for (let i = 0; i <= pieceMax; i++) {
        const offset = maxPacketSizeFrag * i;
        let pieceLen = maxPacketSizeFrag;
        if (i === pieceMax) {
            ipHdr.mf = false;
            pieceLen = replyPacket.byteLength % maxPacketSizeFrag;
            pktData = new ArrayBuffer(hdrLen + pieceLen);
            p8 = new Uint8Array(pktData);
        }

        ipHdr.fragOffset = offset >>> 3;
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

        if (isLoopback) {
            handlePacket(pktData);
        } else {
            sendRaw(pktData);
        }
    }
}
