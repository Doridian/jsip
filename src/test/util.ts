import { ARPPkt } from "../ethernet/arp/index";
import { ETH_TYPE, EthHdr } from "../ethernet/index";
import { ICMPPkt } from "../ethernet/ip/icmp/index";
import { IPHdr, IPPROTO } from "../ethernet/ip/index";
import { TCPPkt } from "../ethernet/ip/tcp/index";
import { DHCPPkt } from "../ethernet/ip/udp/dhcp/index";
import { DNSPkt } from "../ethernet/ip/udp/dns/index";
import { UDPPkt } from "../ethernet/ip/udp/index";

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
