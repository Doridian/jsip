import { logDebug } from "../util/log";
import { Interface } from "./index";

export class InterfaceNone extends Interface {
    public sendPacket(_: ArrayBuffer): void {
        logDebug("Discarding packet sent to none iface");
    }

    public isEthernet(): boolean {
        return false;
    }

    public getMTU(): number {
        return 65535;
    }
}

export const INTERFACE_NONE = new InterfaceNone("none");
