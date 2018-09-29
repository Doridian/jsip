import { IP_BROADCAST, IP_LOOPBACK, IP_NONE, IPAddr } from "./address";

function makeSubnetBitmask(subnetLen: number) {
    if (subnetLen <= 0) {
        return 0;
    }
    return ~((1 << (32 - subnetLen)) - 1);
}

export class IPNet {
    public static fromString(ipStr: string) {
        const ipS = ipStr.split("/");
        const ip = IPAddr.fromString(ipS[0]);
        const subnetLen = parseInt(ipS[1], 10);
        return IPNet.fromIPAndSubnet(ip, subnetLen);
    }

    public static fromIPAndSubnet(ip: IPAddr, subnetLen: number) {
        return new IPNet(ip, makeSubnetBitmask(subnetLen));
    }

    private bitmask: number;
    private mask?: IPAddr;
    private baseIpInt: number;
    private sortmask: number;

    constructor(ip: IPAddr, bitmask: number) {
        this.bitmask = bitmask;
        this.sortmask = bitmask >>> 0;
        this.mask = IPAddr.fromInt32(bitmask);
        this.baseIpInt = ip.toInt() & bitmask;
    }

    public equals(ipNet: IPNet) {
        if (!ipNet) {
            return false;
        }
        return this.bitmask === ipNet.bitmask && this.baseIpInt === ipNet.baseIpInt;
    }

    public toString() {
        return `${IPAddr.fromInt32(this.baseIpInt)}/${this.mask}`;
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

    public getAddress(num: number) {
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
