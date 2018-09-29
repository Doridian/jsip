import { IP_LOOPBACK } from "../ethernet/ip/address";
import { IPNET_LOOPBACK } from "../ethernet/ip/subnet";
import { handlePacket } from "../util/packet";
import { Interface } from "./index";
import { addInterface } from "./stack";

export class InterfaceLoopback extends Interface {
    public sendRaw(msg: ArrayBuffer): void {
        handlePacket(msg, this);
    }

    public getIP() {
        return IP_LOOPBACK;
    }

    public getSubnet() {
        return IPNET_LOOPBACK;
    }

    public useEthernet(): boolean {
        return false;
    }

    public getMTU(): number {
        return 65535;
    }
}

export const INTERFACE_LOOPBACK = new InterfaceLoopback("lo");

export function addLoopbackInterface() {
    addInterface(INTERFACE_LOOPBACK);
}
