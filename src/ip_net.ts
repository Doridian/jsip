import { IPAddr } from "./ip_addr";

export class IPNet {
    public static fromString(ipStr: string) {
        const ipS = ipStr.split("/");
        const ip = IPAddr.fromString(ipS[0]);
        const subnetLen = parseInt(ipS[1], 10);
        return new IPNet(ip, ~((1 << (32 - subnetLen)) - 1));
    }

    public ip?: IPAddr;
    private bitmask = 0;
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
        return this.bitmask === ipNet.bitmask && this.ip!.equals(ipNet.ip!);
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

    public getAddress(num: number) {
        return IPAddr.fromInt32(this.baseIpInt + num);
    }
}

export const IPNETS_MULTICAST = [
    IPNet.fromString("224.0.0.0/14"),
    IPNet.fromString("224.4.0.0/16"),
    IPNet.fromString("232.0.0.0/8"),
    IPNet.fromString("233.0.0.0/8"),
    IPNet.fromString("234.0.0.0/8"),
    IPNet.fromString("239.0.0.0/8"),
];
