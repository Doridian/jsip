import { config } from "../config";
import { ETH_TYPE, EthHdr } from "./index";

type EthHandler = (buffer: ArrayBuffer, offset: number, ethHdr: EthHdr) => void;

const ethHandlers: { [key: number]: EthHandler } = {};

export function handleEthernet(buffer: ArrayBuffer) {
    let offset = 0;

    const ethHdr = EthHdr.fromPacket(buffer, offset);
    if (!ethHdr) {
        return;
    }

    const isBroadcast = ethHdr.daddr!.isBroadcast();

    if (!ethHdr.daddr!.equals(config.ourMac) && !isBroadcast) {
        console.log(`Discarding packet not meant for us, but for ${ethHdr.daddr!.toString()}`);
        return;
    }

    offset += ethHdr.getContentOffset();

    const handler = ethHandlers[ethHdr.ethtype];
    if (handler) {
        handler(buffer, offset, ethHdr);
    }
}

export function registerEthHandler(ethtype: ETH_TYPE, handler: EthHandler) {
    ethHandlers[ethtype] = handler;
}
