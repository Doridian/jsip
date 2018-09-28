import { MACAddr } from "./ethernet/address";
import { IP_NONE, IPAddr } from "./ethernet/ip/address";
import { logDebug } from "./util/log";
import { handlePacket } from "./util/packet";

export interface IInterface {
    getName(): string;
    useEthernet(): boolean;
    getIP(): IPAddr;
    setIP(ip: IPAddr): void;
    getMAC(): MACAddr;
    getMTU(): number;
    sendRaw(msg: ArrayBuffer): void;
}

export abstract class Interface implements IInterface {
    private name: string;
    private ip: IPAddr = IP_NONE;
    private mac: MACAddr = MACAddr.random();

    public constructor(name: string) {
        this.name = name;
    }

    public getName(): string {
        return this.name;
    }

    public getIP() {
        return this.ip;
    }

    public setIP(ip: IPAddr) {
        this.ip = ip;
    }

    public getMAC(): MACAddr {
        return this.mac;
    }

    public abstract sendRaw(_: ArrayBuffer): void;
    public abstract useEthernet(): boolean;
    public abstract getMTU(): number;
}

// tslint:disable-next-line:max-classes-per-file
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
}

// tslint:disable-next-line:max-classes-per-file
export class InterfaceDummy extends Interface {
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

export const INTERFACE_NONE = new InterfaceDummy("none");
export const INTERFACE_LOOPBACK = new InterfaceLoopback("lo");
