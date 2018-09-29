import { IP_LOOPBACK, IPAddr } from "../ethernet/ip/address";
import { IPNET_LOOPBACK } from "../ethernet/ip/subnet";
import { handlePacket } from "../util/packet";
import { Interface } from "./index";
import { addInterface } from "./stack";

export class InterfaceLoopback extends Interface {
    public sendRaw(msg: ArrayBuffer): void {
        handlePacket(msg, this);
    }

    public useEthernet(): boolean {
        return false;
    }

    public getMTU(): number {
        return 65535;
    }

    public isLocalDest(_: IPAddr): boolean {
        return true;
    }
}

export const INTERFACE_LOOPBACK = new InterfaceLoopback("lo");
INTERFACE_LOOPBACK.setIP(IP_LOOPBACK);
INTERFACE_LOOPBACK.setSubnet(IPNET_LOOPBACK);

export function addLoopbackInterface() {
    addInterface(INTERFACE_LOOPBACK);
}
