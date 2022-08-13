import { IP_BROADCAST, IP_LOOPBACK, IPAddr } from "./address.js";

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
    private bits: number | undefined;
    private size: number;
    private creationIp: IPAddr;

    constructor(ip: IPAddr, bitmask: number) {
        this.creationIp = ip;
        this.bitmask = bitmask;
        this.sortmask = bitmask >>> 0;
        this.size = (~bitmask) >>> 0;
        this.mask = IPAddr.fromInt32(bitmask);
        this.baseIpInt = ip.toInt32() & bitmask;
        this.baseIp = IPAddr.fromInt32(this.baseIpInt);
        this.bits = bitmaskToSubnetLen.get(bitmask);
    }

    public equals(ipNet: IPNet) {
        if (!ipNet) {
            return false;
        }
        return this.bitmask === ipNet.bitmask && this.baseIpInt === ipNet.baseIpInt;
    }

    public toString() {
        if (this.bits !== undefined) {
            return `${this.baseIp}/${this.bits}`;
        }
        return `${this.baseIp}/${this.mask}`;
    }

    public contains(ip?: IPAddr) {
        if (!ip) {
            return false;
        }
        return (ip.toInt32() & this.bitmask) === this.baseIpInt;
    }

    public compareTo(ipNet: IPNet) {
        return this.sortmask - ipNet.sortmask;
    }

    public getCreationIP() {
        return this.creationIp;
    }

    public getBaseIP() {
        return this.baseIp;
    }

    public getIPCount() {
        return this.size;
    }

    public getIP(num: number) {
        if (num >= this.size || num < 0) {
            throw new RangeError("Address outside of subnet");
        }
        return IPAddr.fromInt32(this.baseIpInt + num);
    }
}

export const IPNET_ALL = IPNet.fromString("0.0.0.0/0");
export const IPNET_LOOPBACK = IPNet.fromIPAndSubnet(IP_LOOPBACK, 8);
export const IPNET_LINK_LOCAL = IPNet.fromString("169.254.0.0/16");
export const IPNET_BROADCAST = IPNet.fromIPAndSubnet(IP_BROADCAST, 32);
export const IPNET_MULTICAST = IPNet.fromString("224.0.0.0/4");
