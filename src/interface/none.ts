import { logDebug } from "../util/log.js";
import { Interface } from "./index.js";

export class InterfaceNone extends Interface {
    public sendRaw(_: ArrayBuffer): void {
        logDebug("Discarding packet sent to none iface");
    }

    public useEthernet(): boolean {
        return false;
    }

    public getMTU(): number {
        return 65535;
    }
}

export const INTERFACE_NONE = new InterfaceNone("none");
