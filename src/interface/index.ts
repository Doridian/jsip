import { MACAddr } from "../ethernet/address.js";
import { sendGratuitousARP } from "../ethernet/arp/stack.js";
import { IPAddr } from "../ethernet/ip/address.js";
import { addRoute, clearRoutesFor, IPRoute, Metric, recomputeRoutes, removeRoute } from "../ethernet/ip/router.js";
import { IPNet } from "../ethernet/ip/subnet.js";
import { addDHCP, DHCPNegotiator, removeDHCP } from "../ethernet/ip/udp/dhcp/stack.js";
import { addDNSServerFor, clearDNSServersFor, removeDNSServerFor } from "../ethernet/ip/udp/dns/stack.js";
import { handlePacket } from "../util/packet.js";
import { addInterface, removeInterface } from "./stack.js";

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
        recomputeRoutes();
        if (this.isEthernet()) {
            sendGratuitousARP(this);
        }
    }

    public getSubnet() {
        return this.subnet;
    }

    public setSubnet(subnet: IPNet) {
        this.subnet = subnet;
        recomputeRoutes();
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

    public addRoute(route: IPRoute): void {
        addRoute({
            ...route,
            iface: this,
        });
    }

    public removeRoute(route: IPRoute): void {
        removeRoute({
            ...route,
            iface: this,
        });
    }

    public clearRoutes(): void {
        clearRoutesFor(this);
    }

    public addDHCP(metric: number = Metric.DHCPDefault): DHCPNegotiator {
        return addDHCP(this, metric);
    }

    public removeDHCP(): void {
        removeDHCP(this);
    }

    public addDNSServer(ip: IPAddr): void {
        addDNSServerFor(ip, this);
    }

    public removeDNSServer(ip: IPAddr): void {
        removeDNSServerFor(ip, this);
    }

    public clearDNSServers(): void {
        clearDNSServersFor(this);
    }

    public add(): void {
        addInterface(this);
        recomputeRoutes();
    }

    public remove(): void {
        removeInterface(this);
        removeDHCP(this);
        clearRoutesFor(this);
        clearDNSServersFor(this);
    }
}
