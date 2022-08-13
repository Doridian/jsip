import { MACAddr } from "../ethernet/address";
import { IPAddr } from "../ethernet/ip/address";
import { addRoute, flushRoutes as clearRoutes, recomputeRoutes, removeRoute } from "../ethernet/ip/router";
import { IPNet } from "../ethernet/ip/subnet";
import { addDHCP, DHCPNegotiator, removeDHCP } from "../ethernet/ip/udp/dhcp/stack";
import { addDNSServer, clearDNSServers as clearDNSServers, removeDNSServer } from "../ethernet/ip/udp/dns/stack";
import { handlePacket } from "../util/packet";
import { addInterface, deleteInterface as removeInterface } from "./stack";

export interface IInterface {
    getName(): string;
    isEthernet(): boolean;
    getIP(): IPAddr | undefined;
    setIP(ip: IPAddr): void;
    getSubnet(): IPNet | undefined;
    setSubnet(subnet: IPNet): void;
    getMAC(): MACAddr;
    getMTU(): number;
    isConfigured(): boolean;
    isLocalDest(ip: IPAddr): boolean;
    sendPacket(msg: ArrayBuffer): void;
}

export abstract class Interface implements IInterface {
    protected subnet?: IPNet;
    private name: string;
    private ip?: IPAddr;
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
        return !!this.getIP();
    }

    public isLocalDest(ip: IPAddr): boolean {
        return this.ip && this.ip.equals(ip) || false;
    }

    public abstract sendPacket(msg: ArrayBuffer): void;
    public abstract isEthernet(): boolean;
    public abstract getMTU(): number;

    protected handlePacket(packet: ArrayBuffer): void {
        handlePacket(packet, this);
    }

    public addRoute(subnet: IPNet, router?: IPAddr, src?: IPAddr): void {
        addRoute(subnet, router, this, src);
    }

    public removeRoute(subnet: IPNet): void {
        removeRoute(subnet);
    }

    public clearRoutes(): void {
        clearRoutes(this);
    }

    public addDHCP(): DHCPNegotiator {
        return addDHCP(this);
    }

    public removeDHCP(): void {
        removeDHCP(this);
    }

    public addDNSServer(ip: IPAddr): void {
        addDNSServer(ip, this);
    }

    public removeDNSServer(ip: IPAddr): void {
        removeDNSServer(ip, this);
    }

    public clearDNSServers(): void {
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
