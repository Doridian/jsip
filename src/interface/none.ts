import { MACAddr, MAC_NONE } from "../ethernet/address";
import { IPAddr, IP_NONE } from "../ethernet/ip/address";
import { IPNet, IPNET_NONE } from "../ethernet/ip/subnet";
import { logDebug } from "../util/log";
import { IInterface } from "./index";

export class InterfaceNone implements IInterface {
    getName(): string {
        return "none";
    }

    getIP(): IPAddr {
        return IP_NONE;
    }

    setIP(_ip: IPAddr): void { }

    getSubnet(): IPNet {
        return IPNET_NONE;
    }

    setSubnet(_subnet: IPNet): void {  }

    getMAC(): MACAddr {
        return MAC_NONE;
    }

    isConfigured(): boolean {
        return true;
    }

    isLocalDest(_ip: IPAddr): boolean {
        return false;
    }

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

export const INTERFACE_NONE = new InterfaceNone();
