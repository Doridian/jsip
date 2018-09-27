import { config } from "../config";
import { handleIP } from "../ethernet/ip/stack";
import { handleEthernet } from "../ethernet/stack";

export function handlePacket(data: ArrayBuffer) {
    if (config.enableEthernet) {
        handleEthernet(data);
    } else {
        handleIP(data);
    }
}
