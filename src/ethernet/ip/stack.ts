import { IInterface } from "../../interface/index";
import { logDebug, logError } from "../../util/log";
import { ETH_TYPE, EthHdr } from "../index";
import { registerEthHandler } from "../stack";
import { IPHdr } from "./index";
import { reversePathCheck } from "./router";

type IPHandler = (data: ArrayBuffer, offset: number, len: number, ipHdr: IPHdr, iface: IInterface) => void;

const ipHandlers = new Map<number, IPHandler>();

function handlePacket(ipHdr: IPHdr, data: ArrayBuffer, offset: number, iface: IInterface) {
    const len = data.byteLength - offset;

    const handler = ipHandlers.get(ipHdr.protocol);
    if (handler) {
        try {
            handler(data, offset, len, ipHdr, iface);
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

const fragmentCache = new Map<string, Map<number, IPFragmentContainer>>();

export function handleIP(buffer: ArrayBuffer, offset = 0, _: EthHdr, iface: IInterface) {
    const ipHdr = IPHdr.fromPacket(buffer, offset);
    if (!ipHdr) {
        return;
    }

    if (iface.isConfigured()) {
        if (!reversePathCheck(iface, ipHdr.saddr)) {
            logDebug(`Reverse path check failed for src ${ipHdr.saddr} on ${iface.getName()}`);
            return;
        }

        if (ipHdr.daddr.isUnicast() &&
            !iface.isLocalDest(ipHdr.daddr)) {
            logDebug(`${iface.getName()} Discarding packet not meant for us, but for ${ipHdr.daddr}`);
            return;
        }
    }

    const isFrag = ipHdr.mf || ipHdr.fragOffset > 0;
    offset += ipHdr.getContentOffset();

    if (!isFrag) {
        return handlePacket(ipHdr, buffer, offset, iface);
    }

    const ifaceName = iface.getName();
    let ifaceFragmentCache = fragmentCache.get(ifaceName);
    if (!ifaceFragmentCache) {
        ifaceFragmentCache = new Map();
        fragmentCache.set(ifaceName, ifaceFragmentCache);
    }

    const pktId = ipHdr.id + (ipHdr.saddr.toInt() << 16);
    let curFrag = ifaceFragmentCache.get(pktId);
    if (!curFrag) {
        curFrag = {
            fragments: new Map(),
            last: undefined,
            time: Date.now(),
            validUntil: undefined,
        };
        ifaceFragmentCache.set(pktId, curFrag);
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
            return handlePacket(ipHdr, fullData, 0, iface);
        }
    }
}

function timeoutFragments() {
    const cutoff = Date.now() - 30000;
    for (const id of Array.from(fragmentCache.keys())) {
        const myCache = fragmentCache.get(id)!;
        for (const subId of Array.from(myCache.keys())) {
            const frag = myCache.get(subId)!;
            if (frag.time < cutoff) {
                fragmentCache.delete(id);
            }
        }
    }
}

setInterval(timeoutFragments, 1000);

registerEthHandler(ETH_TYPE.IP, handleIP);
