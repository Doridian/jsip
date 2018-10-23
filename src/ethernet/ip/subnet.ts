import { IP_BROADCAST, IP_LOOPBACK, IP_NONE, IPAddr } from "./address.js";

const subnetLenToBitmask: number[] = [];
const bitmaskToSubnetLen = new Map<number, number>();

subnetLenToBitmask[0] = 0;
bitmaskToSubnetLen.set(0, 0);

for (let subnetLen = 1; subnetLen <= 32; subnetLen++) {
    const bitmask = ~((1 << (32 - subnetLen)) - 1);
    subnetLenToBitmask[subnetLen] = bitmask;
    bitmaskToSubnetLen.set(bitmask, subnetLen);
}

export class IPNet {
    public static fromString(ipStr: string) {
        const ipS = ipStr.split("/");
        const ip = IPAddr.fromString(ipS[0]);
        const subnetLen = parseInt(ipS[1], 10);
        return IPNet.fromIPAndSubnet(ip, subnetLen);
    }

    public static fromIPAndSubnet(ip: IPAddr, subnetLen: number) {
        return new IPNet(ip, subnetLenToBitmask[subnetLen]);
    }

    private bitmask: number;
    private mask: IPAddr;
    private baseIp: IPAddr;
    private baseIpInt: number;
    private sortmask: number;
    private subnetLen: number | undefined;

    constructor(ip: IPAddr, bitmask: number) {
        this.bitmask = bitmask;
        this.sortmask = bitmask >>> 0;
        this.mask = IPAddr.fromInt32(bitmask);
        this.baseIpInt = ip.toInt() & bitmask;
        this.baseIp = IPAddr.fromInt32(this.baseIpInt);
        this.subnetLen = bitmaskToSubnetLen.get(bitmask);
    }

    public equals(ipNet: IPNet) {
        if (!ipNet) {
            return false;
        }
        return this.bitmask === ipNet.bitmask && this.baseIpInt === ipNet.baseIpInt;
    }

    public toString() {
        if (this.subnetLen !== undefined) {
            return `${this.baseIp}/${this.subnetLen}`;
        }
        return `${this.baseIp}/${this.mask}`;
    }

    public contains(ip?: IPAddr) {
        if (!ip) {
            return false;
        }
        return (ip.toInt() & this.bitmask) === this.baseIpInt;
    }

    public compareTo(ipNet: IPNet) {
        return this.sortmask - ipNet.sortmask;
    }

    public getBaseIP() {
        return this.baseIp;
    }

    public getIP(num: number) {
        return IPAddr.fromInt32(this.baseIpInt + num);
    }
}

export const IPNETS_MULTICAST = [
    IPNet.fromString("224.0.0.0/4"),
];

export const IPNET_NONE = IPNet.fromIPAndSubnet(IP_NONE, 8);
export const IPNET_ALL = IPNet.fromIPAndSubnet(IP_NONE, 0);
export const IPNET_LOOPBACK = IPNet.fromIPAndSubnet(IP_LOOPBACK, 8);
export const IPNET_BROADCAST = IPNet.fromIPAndSubnet(IP_BROADCAST, 32);
export const IPNET_LINK_LOCAL = IPNet.fromString("169.254.0.0/16");

IPAddr.setMulticastNets(IPNETS_MULTICAST);
