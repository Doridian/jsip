import { config } from "../../config";
import { logDebug, logError } from "../../util/log";
import { ETH_TYPE } from "../index";
import { registerEthHandler } from "../stack";
import { IP_NONE } from "./address";
import { IPHdr } from "./index";

type IPHandler = (data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr) => void;

const ipHandlers = new Map<number, IPHandler>();

function handlePacket(ipHdr: IPHdr, data: ArrayBuffer, offset: number) {
    const len = data.byteLength - offset;

    const handler = ipHandlers.get(ipHdr.protocol);
    if (handler) {
        try {
            handler(data, offset, len, ipHdr);
        } catch (e) {
            logError(e.stack || e);
        }
    }
}

export function registerIpHandler(iptype: number, handler: IPHandler) {
    ipHandlers.set(iptype, handler);
}

interface IPFragment {
    ipHdr: IPHdr;
    buffer: ArrayBuffer;
    offset: number;
    len: number;
}

interface IPFragmentContainer {
    time: number;
    last?: number;
    validUntil?: number;
    fragments: Map<number, IPFragment>;
}

const fragmentCache = new Map<number, IPFragmentContainer>();

export function handleIP(buffer: ArrayBuffer, offset = 0) {
    const ipHdr = IPHdr.fromPacket(buffer, offset);
    if (!ipHdr || !ipHdr.daddr) {
        return;
    }

    if (config.ourIp !== IP_NONE &&
        ipHdr.daddr.isUnicast() &&
        !ipHdr.daddr.isLoopback() &&
        !ipHdr.daddr.equals(config.ourIp)) {
        logDebug(`Discarding packet not meant for us, but for ${ipHdr.daddr.toString()}`);
        return;
    }

    const isFrag = ipHdr.mf || ipHdr.fragOffset > 0;
    offset += ipHdr.getContentOffset();

    if (!isFrag) {
        return handlePacket(ipHdr, buffer, offset);
    }

    const pktId = ipHdr.id + (ipHdr.saddr.toInt() << 16);
    let curFrag = fragmentCache.get(pktId);
    if (!curFrag) {
        curFrag = {
            fragments: new Map(),
            last: undefined,
            time: Date.now(),
            validUntil: undefined,
        };
        fragmentCache.set(pktId, curFrag);
    }

    const fragOffset = ipHdr.fragOffset << 3;
    curFrag.fragments.set(fragOffset, {
        buffer,
        ipHdr,
        len: buffer.byteLength - offset,
        offset,
    });
    if (!ipHdr.mf) {
        curFrag.last = fragOffset;
    }
    if (fragOffset === 0) {
        curFrag.validUntil = 0;
    }

    // Check if we got all fragments
    if (curFrag.validUntil !== undefined && curFrag.last !== undefined) {
        let curPiecePos = curFrag.validUntil;
        let curPiece: IPFragment | undefined = curFrag.fragments.get(curPiecePos)!;

        let gotAll = false;
        while (true) {
            curPiecePos += curPiece.len;
            curPiece = curFrag.fragments.get(curPiecePos);
            if (!curPiece) {
                break;
            }
            if (!curPiece.ipHdr.mf) {
                gotAll = true;
                break;
            }
        }

        if (gotAll) {
            const fullData = new ArrayBuffer(curFrag.fragments.get(curFrag.last)!.len + curFrag.last);
            const d8 = new Uint8Array(fullData);
            curPiecePos = 0;
            curPiece = curFrag.fragments.get(curPiecePos)!;
            while (true) {
                const p8 = new Uint8Array(curPiece.buffer, curPiece.offset);
                for (let i = 0; i < p8.length; i++) {
                    d8[curPiecePos + i] = p8[i];
                }
                if (!curPiece.ipHdr.mf) {
                    break;
                }
                curPiecePos += curPiece.len;
                curPiece = curFrag.fragments.get(curPiecePos)!;
            }
            return handlePacket(ipHdr, fullData, 0);
        }
    }
}

function timeoutFragments() {
    const cutoff = Date.now() - 30000;
    for (const id of Array.from(fragmentCache.keys())) {
        const frag = fragmentCache.get(id)!;
        if (frag.time < cutoff) {
            fragmentCache.delete(id);
        }
    }
}

setInterval(timeoutFragments, 1000);

registerEthHandler(ETH_TYPE.IP, handleIP);
