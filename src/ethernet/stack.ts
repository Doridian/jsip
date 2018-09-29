import { IInterface } from "../interface/index.js";
import { logDebug } from "../util/log.js";
import { ETH_TYPE, EthHdr } from "./index.js";

type EthHandler = (buffer: ArrayBuffer, offset: number, ethHdr: EthHdr, iface: IInterface) => void;

const ethHandlers = new Map<number, EthHandler>();

export function handleEthernet(buffer: ArrayBuffer, iface: IInterface) {
    let offset = 0;

    const ethHdr = EthHdr.fromPacket(buffer, offset);

    if (!ethHdr.daddr.equals(iface.getMAC()) && !ethHdr.daddr.isBroadcast()) {
        logDebug(`Discarding packet not meant for us, but for ${ethHdr.daddr.toString()}`);
        return;
    }

    offset += ethHdr.getContentOffset();

    const handler = ethHandlers.get(ethHdr.ethtype);
    if (handler) {
        handler(buffer, offset, ethHdr, iface);
    }
}

export function registerEthHandler(ethtype: ETH_TYPE, handler: EthHandler) {
    ethHandlers.set(ethtype, handler);
}
