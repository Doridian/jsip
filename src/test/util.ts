import { MACAddr } from "../ethernet/address.js";
import { ARPPkt } from "../ethernet/arp/index.js";
import { ETH_TYPE, EthHdr } from "../ethernet/index.js";
import { IPAddr } from "../ethernet/ip/address.js";
import { ICMPPkt } from "../ethernet/ip/icmp/index.js";
import { IPHdr, IPPROTO } from "../ethernet/ip/index.js";
import { TCPPkt } from "../ethernet/ip/tcp/index.js";
import { DHCPPkt } from "../ethernet/ip/udp/dhcp/index.js";
import { DNSPkt } from "../ethernet/ip/udp/dns/index.js";
import { UDPPkt } from "../ethernet/ip/udp/index.js";

export function decodeHexString(str: string) {
    const res = new ArrayBuffer(str.length / 2);
    const res8 = new Uint8Array(res);
    for (let i = 0; i < str.length; i += 2) {
        res8[i / 2] = parseInt(str.substr(i, 2), 16);
    }
    return res;
}

export interface IPacketParts {
    eth?: EthHdr;

    ip?: IPHdr;
    arp?: ARPPkt;

    udp?: UDPPkt;
    tcp?: TCPPkt;
    icmp?: ICMPPkt;

    dns?: DNSPkt;
    dhcp?: DHCPPkt;
}

export function parsePacketParts(packet: ArrayBuffer): IPacketParts {
    const ethHdr = EthHdr.fromPacket(packet, 0);
    let offset = ethHdr.getContentOffset();
    switch (ethHdr.ethtype) {
        case ETH_TYPE.ARP:
            return { eth: ethHdr, arp: ARPPkt.fromPacket(packet, offset) };
        case ETH_TYPE.IP:
            const ipHdr = IPHdr.fromPacket(packet, offset);
            if (!ipHdr) {
                return { eth: ethHdr };
            }
            offset += ipHdr.getContentOffset();
            const len = ipHdr.getContentLength();
            switch (ipHdr.protocol) {
                case IPPROTO.ICMP:
                    return { eth: ethHdr, ip: ipHdr, icmp: ICMPPkt.fromPacket(packet, offset, len) };
                case IPPROTO.UDP:
                    const udpPkt = UDPPkt.fromPacket(packet, offset, len, ipHdr);
                    const data = udpPkt.data!;

                    const udpBuffer = data.buffer as ArrayBuffer;
                    const udpOffset = data.byteOffset;

                    let usePort = udpPkt.sport;
                    if (udpPkt.dport < 1024) {
                        usePort = udpPkt.dport;
                    }

                    switch (usePort) {
                        case 53:
                            return {
                                dns: DNSPkt.fromPacket(udpBuffer, udpOffset),
                                eth: ethHdr,
                                ip: ipHdr,
                                udp: udpPkt,
                            };
                        case 67:
                        case 68:
                            return {
                                dhcp: DHCPPkt.fromPacket(udpBuffer, udpOffset),
                                eth: ethHdr,
                                ip: ipHdr,
                                udp: udpPkt,
                            };
                        default:
                            return { eth: ethHdr, ip: ipHdr, udp: udpPkt };
                    }
                case IPPROTO.TCP:
                    return { eth: ethHdr, ip: ipHdr, tcp: TCPPkt.fromPacket(packet, offset, len, ipHdr) };
                default:
                    return { eth: ethHdr, ip: ipHdr };
            }
        default:
            return { eth: ethHdr };
    }
}

function compareIPOrMAC(a: IPAddr | MACAddr | undefined, b: IPAddr | MACAddr | undefined): boolean {
    if (!a || !b) {
        return !a && !b;
    }

    if (a instanceof IPAddr) {
        if (!(b instanceof IPAddr)) {
            return false;
        }
        return a.equals(b);
    }

    if (!(b instanceof MACAddr)) {
        return false;
    }
    return a.equals(b);
}

export class AssertionError extends Error {
    constructor(public readonly expected: unknown, public readonly actual: unknown) {
        super(`Actual: ${actual}; Expected: ${expected}`);
    }
}

export function expect(actual: unknown) {
    return {
        to: {
            equal(expected: unknown) {
                if (actual !== expected) {
                    throw new AssertionError(expected, actual);
                }
            },
            deep: {
                equal(expected: MACAddr | IPAddr) {
                    if (!compareIPOrMAC(actual as typeof expected, expected)) {
                        throw new AssertionError(expected, actual);
                    }
                }
            }
        }
    }
}
