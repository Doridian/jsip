import { EthHdr } from "../ethernet/index.js";
import { handleIP } from "../ethernet/ip/stack.js";
import { handleEthernet } from "../ethernet/stack.js";
import { IInterface } from "../interface/index.js";

const ethDummy = new EthHdr();

export function handlePacket(data: ArrayBuffer, iface: IInterface) {
    if (iface.useEthernet()) {
        handleEthernet(data, iface);
    } else {
        handleIP(data, 0, ethDummy, iface);
    }
}
