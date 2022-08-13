import { IInterface } from "../interface/index.js";
import { logDebug } from "../util/log.js";
import { ETH_TYPE, EthHdr } from "./index.js";

export interface IEthHandler {
    gotPacket(buffer: ArrayBuffer, offset: number, ethHdr: EthHdr, iface: IInterface): void;
}

const ethHandlers = new Map<number, IEthHandler>();

export function handleEthernet(buffer: ArrayBuffer, iface: IInterface) {
    let offset = 0;

    const ethHdr = EthHdr.fromPacket(buffer, offset);

    if (!ethHdr.daddr!.equals(iface.getMAC()) && !ethHdr.daddr!.isBroadcast()) {
        logDebug(`Discarding packet not meant for us, but for ${ethHdr.daddr!.toString()}`);
        return;
    }

    offset += ethHdr.getContentOffset();

    const handler = ethHandlers.get(ethHdr.ethtype);
    if (handler) {
        handler.gotPacket(buffer, offset, ethHdr, iface);
    }
}

export function registerEthHandler(ethtype: ETH_TYPE, handler: IEthHandler) {
    if (ethHandlers.has(ethtype)) {
        return false;
    }
    ethHandlers.set(ethtype, handler);
    return true;
}
