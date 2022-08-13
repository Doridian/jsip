import { MACAddr } from "../ethernet/address";
import { IP_NONE, IPAddr } from "../ethernet/ip/address";
import { addRoute, flushRoutes as clearRoutes, recomputeRoutes, removeRoute } from "../ethernet/ip/router";
import { IPNet, IPNET_NONE } from "../ethernet/ip/subnet";
import { addDHCP, removeDHCP } from "../ethernet/ip/udp/dhcp/stack";
import { addDNSServer, clearDNSServers as clearDNSServers, removeDNSServer } from "../ethernet/ip/udp/dns/stack";
import { handlePacket } from "../util/packet";
import { addInterface, deleteInterface as removeInterface } from "./stack";

export interface IInterface {
    getName(): string;
    isEthernet(): boolean;
    getIP(): IPAddr;
    setIP(ip: IPAddr): void;
    getSubnet(): IPNet;
    setSubnet(subnet: IPNet): void;
    getMAC(): MACAddr;
    getMTU(): number;
    isConfigured(): boolean;
    isLocalDest(ip: IPAddr): boolean;
    sendPacket(msg: ArrayBuffer): void;
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

    public abstract sendPacket(msg: ArrayBuffer): void;
    public abstract isEthernet(): boolean;
    public abstract getMTU(): number;

    protected handlePacket(packet: ArrayBuffer): void {
        handlePacket(packet, this);
    }

    public addRoute(subnet: IPNet, router: IPAddr, src?: IPAddr): void {
        addRoute(subnet, router, this, src);
    }

    public removeRoute(subnet: IPNet) {
        removeRoute(subnet);
    }

    public clearRoutes() {
        clearRoutes(this);
    }

    public addDHCP() {
        addDHCP(this);
    }

    public removeDHCP() {
        removeDHCP(this);
    }

    public addDNSServer(ip: IPAddr) {
        addDNSServer(ip, this);
    }

    public removeDNSServer(ip: IPAddr) {
        removeDNSServer(ip, this);
    }

    public clearDNSServers() {
        clearDNSServers(this);
    }

    public add(): void {
        addInterface(this);
        recomputeRoutes();
    }

    public remove(): void {
        removeInterface(this);
        removeDHCP(this);
        clearRoutes(this);
        clearDNSServers(this);
    }
}
