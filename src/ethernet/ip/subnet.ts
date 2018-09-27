import { IP_BROADCAST, IP_NONE, IPAddr } from "./address";

function makeSubnetBitmask(subnetLen: number) {
    return ~((1 << (32 - subnetLen)) - 1);
}

export class IPNet {
    public static fromString(ipStr: string) {
        const ipS = ipStr.split("/");
        const ip = IPAddr.fromString(ipS[0]);
        const subnetLen = parseInt(ipS[1], 10);
        return new IPNet(ip, makeSubnetBitmask(subnetLen));
    }

    public ip: IPAddr;
    public bitmask = 0;
    private mask?: IPAddr;
    private baseIpInt = 0;

    constructor(ip: IPAddr, bitmask: number) {
        this.ip = ip;
        this.bitmask = bitmask;
        this.mask = IPAddr.fromInt32(bitmask);
        this.baseIpInt = ip.toInt() & bitmask;
    }

    public equals(ipNet: IPNet) {
        if (!ipNet) {
            return false;
        }
        return this.bitmask === ipNet.bitmask && this.ip.equals(ipNet.ip);
    }

    public toString() {
        return `${this.ip}/${this.mask}`;
    }

    public contains(ip?: IPAddr) {
        if (!ip) {
            return false;
        }
        return (ip.toInt() & this.bitmask) === this.baseIpInt;
    }

    public compareTo(ipNet: IPNet) {
        return (this.bitmask >>> 0) - (ipNet.bitmask >>> 0);
    }

    public getAddress(num: number) {
        return IPAddr.fromInt32(this.baseIpInt + num);
    }
}

export const IPNETS_MULTICAST = [
    IPNet.fromString("224.0.0.0/4"),
];

export const IPNET_NONE = new IPNet(IP_NONE, makeSubnetBitmask(8));
export const IPNET_ALL = new IPNet(IP_NONE, 0);
export const IPNET_LOOPBACK = IPNet.fromString("127.0.0.0/8");
export const IPNET_BROADCAST = new IPNet(IP_BROADCAST, makeSubnetBitmask(32));
export const IPNET_LINK_LOCAL = IPNet.fromString("169.254.0.0/16");

IPAddr.setMulticastNets(IPNETS_MULTICAST);
