import { MACAddr } from "../ethernet/address";
import { IP_NONE, IPAddr } from "../ethernet/ip/address";
import { IPNet, IPNET_NONE } from "../ethernet/ip/subnet";

export interface IInterface {
    getName(): string;
    useEthernet(): boolean;
    getIP(): IPAddr;
    setIP(ip: IPAddr): void;
    getSubnet(): IPNet;
    setSubnet(subnet: IPNet): void;
    getMAC(): MACAddr;
    getMTU(): number;
    isConfigured(): boolean;
    isLocalDest(ip: IPAddr): boolean;
    sendRaw(msg: ArrayBuffer): void;
}

export abstract class Interface implements IInterface {
    protected subnet: IPNet = IPNET_NONE;
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

    public getSubnet() {
        return this.subnet;
    }

    public setSubnet(subnet: IPNet) {
        this.subnet = subnet;
    }

    public getMAC(): MACAddr {
        return this.mac;
    }

    public isConfigured(): boolean {
        return this.getIP() !== IP_NONE;
    }

    public isLocalDest(ip: IPAddr): boolean {
        if (!this.isConfigured()) {
            return true;
        }

        return this.ip.equals(ip);
    }

    public abstract sendRaw(msg: ArrayBuffer): void;
    public abstract useEthernet(): boolean;
    public abstract getMTU(): number;
}
