import { config } from "../../config";
import { logDebug } from "../../util/log";
import { ETH_TYPE } from "../index";
import { registerEthHandler } from "../stack";
import { IP_NONE } from "./address";
import { IPHdr } from "./index";

type IPHandler = (data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) => void;

const ipHandlers: { [key: number]: IPHandler } = {};

function handlePacket(ipHdr: IPHdr, data: ArrayBuffer, offset: number) {
    const len = data.byteLength - offset;

    const handler = ipHandlers[ipHdr.protocol];
    if (handler) {
        handler(data, offset, len, ipHdr);
    }
}

export function registerIpHandler(iptype: number, handler: IPHandler) {
    ipHandlers[iptype] = handler;
}

interface IPFragment {
    time: number;
    last?: number;
    validUntil?: number;
    [key: number]: {
        ipHdr: IPHdr;
        buffer: ArrayBuffer;
        offset: number;
        len: number;
    };
}

const fragmentCache: { [key: string]: IPFragment } = {};

export function handleIP(buffer: ArrayBuffer, offset = 0) {
    const ipHdr = IPHdr.fromPacket(buffer, offset);
    if (!ipHdr || !ipHdr.daddr) {
        return;
    }

    if (config.ourIp !== IP_NONE && ipHdr.daddr.isUnicast() && !ipHdr.daddr.equals(config.ourIp)) {
        logDebug(`Discarding packet not meant for us, but for ${ipHdr.daddr.toString()}`);
        return;
    }

    const isFrag = ipHdr.mf || ipHdr.fragOffset > 0;
    offset += ipHdr.getContentOffset();

    if (!isFrag) {
        return handlePacket(ipHdr, buffer, offset);
    }

    const pktId = ipHdr.id + (ipHdr.saddr.toInt() << 16);
    let curFrag = fragmentCache[pktId];
    if (!curFrag) {
        curFrag = {
            last: undefined,
            time: Date.now(),
            validUntil: undefined,
        };
        fragmentCache[pktId] = curFrag;
    }

    const fragOffset = ipHdr.fragOffset << 3;
    curFrag[fragOffset] = {
        buffer,
        ipHdr,
        len: buffer.byteLength - offset,
        offset,
    };
    if (!ipHdr.mf) {
        curFrag.last = fragOffset;
    }
    if (ipHdr.fragOffset === 0) {
        curFrag.validUntil = 0;
    }

    // Check if we got all fragments
    if (curFrag.validUntil !== undefined && curFrag.last !== undefined) {
        let curPiecePos = curFrag.validUntil;
        let curPiece = curFrag[curPiecePos];
        let gotAll = false;
        while (true) {
            curPiecePos += curPiece.len;
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
            const fullData = new ArrayBuffer(curFrag[curFrag.last].len + curFrag.last);
            const d8 = new Uint8Array(fullData);
            curPiecePos = 0;
            curPiece = curFrag[curPiecePos];
            while (true) {
                const p8 = new Uint8Array(curPiece.buffer, curPiece.offset);
                for (let i = 0; i < p8.length; i++) {
                    d8[curPiecePos + i] = p8[i];
                }
                if (!curPiece.ipHdr.mf) {
                    break;
                }
                curPiecePos += curPiece.len;
                curPiece = curFrag[curPiecePos];
            }
            return handlePacket(ipHdr, fullData, 0);
        }
    }
}

function timeoutFragments() {
    const cutoff = Date.now() - 30000;
    for (const id of Object.keys(fragmentCache)) {
        const frag = fragmentCache[id];
        if (frag.time < cutoff) {
            delete fragmentCache[id];
        }
    }
}

setInterval(timeoutFragments, 1000);

registerEthHandler(ETH_TYPE.IP, handleIP);
