import { configOut } from "../../../../config";
import { IInterface } from "../../../../interface";
import { VoidCB } from "../../../../util/index";
import { logDebug } from "../../../../util/log";
import { MAC_NONE, MACAddr } from "../../../address";
import { ARP_HLEN, ARP_HTYPE } from "../../../arp/index";
import { IP_BROADCAST, IP_NONE, IPAddr } from "../../address";
import { IPHdr, IPPROTO } from "../../index";
import { addRoute, flushRoutes } from "../../router";
import { sendIPPacket } from "../../send";
import { IPNet, IPNET_ALL } from "../../subnet";
import { addDNSServer, flushDNSServers } from "../dns/index";
import { UDPPkt } from "../index";
import { udpListen } from "../stack";

const DHCP_MAGIC = new Uint8Array([0x63, 0x82, 0x53, 0x63]);
const DHCP_MAGIC_OFFSET = 236;

const enum DHCP_OPTION {
    MODE = 53,
    SERVER = 54,
    IP = 50,
    OPTIONS = 55,
    SUBNET = 1,
    ROUTER = 3,
    DNS = 6,
    LEASETIME = 51,
    CLASSLESS_STATIC_ROUTE = 121,
}

const enum DHCP_MODE {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    ACK = 5,
    NACK = 6,
}

let ourDHCPXID: number | undefined;
let ourDHCPSecs = 0;
let dhcpRenewTimer: number | undefined;
let dhcpInInitialConfig = false;
let dhcpServer: IPAddr = IP_BROADCAST;
let dhcpDoneCB: VoidCB | undefined;

class DHCPPkt {
    public static fromPacket(packet: ArrayBuffer, offset: number) {
        const data = new Uint8Array(packet, offset);

        const dhcp = new DHCPPkt();
        dhcp.op = data[0];
        dhcp.htype = data[1];
        dhcp.hlen = data[2];
        dhcp.hops = data[3];
        dhcp.xid = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
        dhcp.secs = data[9] + (data[8] << 8);
        dhcp.flags = data[11] + (data[10] << 8);
        dhcp.ciaddr = IPAddr.fromByteArray(data, 12);
        dhcp.yiaddr = IPAddr.fromByteArray(data, 16);
        dhcp.siaddr = IPAddr.fromByteArray(data, 20);
        dhcp.giaddr = IPAddr.fromByteArray(data, 24);
        dhcp.chaddr = MACAddr.fromByteArray(data, 28);

        if (data[DHCP_MAGIC_OFFSET] !== DHCP_MAGIC[0] ||
            data[DHCP_MAGIC_OFFSET + 1] !== DHCP_MAGIC[1] ||
            data[DHCP_MAGIC_OFFSET + 2] !== DHCP_MAGIC[2] ||
            data[DHCP_MAGIC_OFFSET + 3] !== DHCP_MAGIC[3]) {
            throw new Error("Invalid DHCP magic");
        }

        let i = DHCP_MAGIC_OFFSET + 4;
        let gotEnd = false;
        while (i < data.byteLength) {
            const optId = data[i];
            if (optId === 0xFF) {
                gotEnd = true;
                break;
            }

            const optLen = data[i + 1];
            dhcp.options.set(optId, new Uint8Array(packet, offset + i + 2, optLen));
            i += optLen + 2;
        }

        if (!gotEnd) {
            throw new Error("Invalid DHCP end");
        }

        return dhcp;
    }

    public op = 1;
    public htype = ARP_HTYPE;
    public hlen = ARP_HLEN;
    public hops = 0;
    public xid = ourDHCPXID!;
    public secs = ourDHCPSecs;
    public flags = 0;
    public ciaddr: IPAddr = IP_NONE;
    public yiaddr: IPAddr = IP_NONE;
    public siaddr: IPAddr = IP_NONE;
    public giaddr: IPAddr = IP_NONE;
    public chaddr = MAC_NONE;
    public options = new Map<DHCP_OPTION, Uint8Array>();

    public getFullLength() {
        let optLen = 1; // 0xFF always needed
        this.options.forEach((opt) => {
            optLen += 2 + opt.byteLength;
        });
        return DHCP_MAGIC_OFFSET + 4 + optLen;
    }

    public toPacket(array: ArrayBuffer, offset: number) {
        return this._toPacket(new Uint8Array(array, offset));
    }

    public toBytes() {
        const packet = new Uint8Array(this.getFullLength());
        this._toPacket(packet);
        return packet;
    }

    public _toPacket(packet: Uint8Array) {
        packet[0] = this.op;
        packet[1] = this.htype;
        packet[2] = this.hlen;
        packet[3] = this.hops;
        packet[4] = (this.xid >>> 24) & 0xFF;
        packet[5] = (this.xid >>> 16) & 0xFF;
        packet[6] = (this.xid >>> 8) & 0xFF;
        packet[7] = this.xid & 0xFF;
        packet[8] = (this.secs >>> 8) & 0xFF;
        packet[9] = this.secs & 0xFF;
        packet[10] = (this.flags >>> 8) & 0xFF;
        packet[11] = this.flags & 0xFF;
        this.ciaddr.toBytes(packet, 12);
        this.yiaddr.toBytes(packet, 16);
        this.siaddr.toBytes(packet, 20);
        this.giaddr.toBytes(packet, 24);
        this.chaddr.toBytes(packet, 28);
        packet[DHCP_MAGIC_OFFSET] = DHCP_MAGIC[0];
        packet[DHCP_MAGIC_OFFSET + 1] = DHCP_MAGIC[1];
        packet[DHCP_MAGIC_OFFSET + 2] = DHCP_MAGIC[2];
        packet[DHCP_MAGIC_OFFSET + 3] = DHCP_MAGIC[3];

        let optPos = DHCP_MAGIC_OFFSET + 4;
        this.options.forEach((opt, optId) => {
            const optLen = opt.byteLength;
            packet[optPos] = optId;
            packet[optPos + 1] = optLen;
            for (let i = 0; i < optLen; i++) {
                packet[optPos + 2 + i] = opt[i];
            }
            optPos += 2 + opt.byteLength;
        });
        packet[optPos] = 0xFF;

        return optPos;
    }
}

function addDHCPOptions(pkt: DHCPPkt, mode: DHCP_MODE) {
    pkt.options.set(DHCP_OPTION.MODE, new Uint8Array([mode]));
    pkt.options.set(DHCP_OPTION.OPTIONS, new Uint8Array([
        DHCP_OPTION.ROUTER,
        DHCP_OPTION.SUBNET,
        DHCP_OPTION.DNS,
        DHCP_OPTION.LEASETIME,
        DHCP_OPTION.SERVER,
        DHCP_OPTION.IP,
        DHCP_OPTION.CLASSLESS_STATIC_ROUTE,
    ]));
}

function makeDHCPDiscover(iface: IInterface) {
    const pkt = new DHCPPkt();
    pkt.chaddr = iface.getMAC();
    addDHCPOptions(pkt, DHCP_MODE.DISCOVER);
    return makeDHCPUDP(pkt);
}

function makeDHCPRequest(ip: IPAddr, server: IPAddr, iface: IInterface) {
    const pkt = new DHCPPkt();
    pkt.chaddr = iface.getMAC();
    addDHCPOptions(pkt, DHCP_MODE.REQUEST);
    pkt.options.set(DHCP_OPTION.IP, ip.toByteArray());
    pkt.options.set(DHCP_OPTION.SERVER, server.toByteArray());
    return makeDHCPUDP(pkt);
}

function makeDHCPRequestFromOffer(offer: DHCPPkt, iface: IInterface) {
    return makeDHCPRequest(offer.yiaddr, offer.siaddr, iface);
}

function makeDHCPRenewRequest(iface: IInterface) {
    return makeDHCPRequest(iface.getIP(), dhcpServer, iface);
}

function makeDHCPUDP(dhcp: DHCPPkt) {
    const pkt = new UDPPkt();
    pkt.data = dhcp.toBytes();
    pkt.sport = 68;
    pkt.dport = 67;
    return pkt;
}

function makeDHCPIP(iface: IInterface, unicast: boolean = false) {
    const ip = new IPHdr();
    ip.protocol = IPPROTO.UDP;
    if (unicast) {
        ip.saddr = iface.getIP();
        ip.daddr = dhcpServer;
    } else {
        ip.saddr = IP_NONE;
        ip.daddr = IP_BROADCAST;
    }
    ip.df = true;
    return ip;
}

function byteArrayToIpAddrs(array: Uint8Array) {
    const res = [];
    for (let i = 0; i < array.byteLength; i += 4) {
        res.push(IPAddr.fromByteArray(array, i));
    }
    return res;
}

udpListen(68, (data: Uint8Array, _: IPHdr, iface: IInterface) => {
    const packet = data.buffer;
    const offset = data.byteOffset;

    const dhcp = DHCPPkt.fromPacket(packet, offset);
    if (dhcp.op !== 2 || dhcp.xid !== ourDHCPXID) {
        return;
    }

    if (dhcpRenewTimer !== undefined) {
        clearTimeout(dhcpRenewTimer);
        dhcpRenewTimer = undefined;
    }

    switch (dhcp.options.get(DHCP_OPTION.MODE)![0]) {
        case DHCP_MODE.OFFER:
            logDebug("Got DHCP offer, sending DHCP request...");
            sendIPPacket(makeDHCPIP(iface), makeDHCPRequestFromOffer(dhcp, iface), iface);
            break;
        case DHCP_MODE.ACK:
            flushRoutes();

            const dhcpOptIp = dhcp.options.get(DHCP_OPTION.IP);
            const ourIp = dhcpOptIp ?
                IPAddr.fromByteArray(dhcpOptIp, 0) :
                dhcp.yiaddr;

            iface.setIP(ourIp);

            let subnet;
            const subnetDHCP = dhcp.options.get(DHCP_OPTION.SUBNET);
            if (subnetDHCP) {
                subnet = new IPNet(
                    ourIp,
                    subnetDHCP[3] + (subnetDHCP[2] << 8) + (subnetDHCP[1] << 16) + (subnetDHCP[0] << 24),
                );
            } else {
                subnet = IPNet.fromString(`${ourIp}/32`);
            }

            addRoute(subnet, IP_NONE, iface);

            const dhcpServerRaw = dhcp.options.get(DHCP_OPTION.SERVER);
            dhcpServer = dhcpServerRaw ?
                IPAddr.fromByteArray(dhcpServerRaw, 0) :
                dhcp.siaddr;

            const dhcpRouterRaw = dhcp.options.get(DHCP_OPTION.ROUTER);
            if (dhcpRouterRaw) {
                addRoute(IPNET_ALL, IPAddr.fromByteArray(dhcpRouterRaw, 0), iface);
            }

            const routesRaw = dhcp.options.get(DHCP_OPTION.CLASSLESS_STATIC_ROUTE);
            if (routesRaw) {
                for (let i = 0; i < routesRaw.byteLength; i++) {
                    const subnetLen = routesRaw[i];
                    const optLen = Math.ceil(subnetLen / 8);

                    i++;
                    const route = IPNet.fromIPAndSubnet(IPAddr.fromPartialByteArray(routesRaw, i, optLen), subnetLen);
                    i += optLen;
                    const ip = IPAddr.fromByteArray(routesRaw, i);
                    i += 3;

                    addRoute(route, ip, iface);
                }
            }

            flushDNSServers();
            const dnsServersRaw = dhcp.options.get(DHCP_OPTION.DNS);
            if (dnsServersRaw) {
                const dnsServers = byteArrayToIpAddrs(dnsServersRaw);
                dnsServers.forEach((server) => addDNSServer(server));
            }

            const rawTtl = dhcp.options.get(DHCP_OPTION.LEASETIME);
            const ttl = rawTtl ?
                (rawTtl[3] + (rawTtl[2] << 8) + (rawTtl[1] << 16) + (rawTtl[0] << 24)) >>> 0 :
                300;

            if (dhcpInInitialConfig) {
                dhcpInInitialConfig = false;
                configOut();
            }
            ourDHCPXID = undefined;

            logDebug(`DHCP TTL: ${ttl}`);
            const ttlHalftime = ((ttl * 1000) / 2) + 1000;
            dhcpRenewTimer = setTimeout(dhcpRenew, ttlHalftime, iface, (ttl * 1000) - ttlHalftime);

            if (dhcpDoneCB) {
                dhcpDoneCB();
                dhcpDoneCB = undefined;
            }
            break;
        case DHCP_MODE.NACK:
            setTimeout(() => dhcpNegotiate(iface), 0);
            break;
    }
});

export function dhcpNegotiate(iface: IInterface, cb?: VoidCB, secs = 0) {
    if (cb) {
        dhcpDoneCB = cb;
    }

    dhcpInInitialConfig = true;
    if (dhcpRenewTimer !== undefined) {
        clearTimeout(dhcpRenewTimer);
        dhcpRenewTimer = undefined;
    }

    if (secs === 0) {
        ourDHCPXID = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
        logDebug(`DHCP Initial XID ${(ourDHCPXID >>> 0).toString(16)}`);
    } else {
        logDebug(`DHCP Initial retry: secs = ${secs}`);
    }
    ourDHCPSecs = secs;

    dhcpRenewTimer = setTimeout(() => dhcpNegotiate(iface, undefined, secs + 5), 5000);
    sendIPPacket(makeDHCPIP(iface), makeDHCPDiscover(iface), iface);
}

function dhcpRenew(iface: IInterface, renegotiateAfter: number = 0) {
    if (renegotiateAfter) {
        dhcpRenewTimer = setTimeout(() => dhcpNegotiate(iface), renegotiateAfter);
    }

    ourDHCPSecs = 0;
    ourDHCPXID = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
    logDebug(`DHCP Renew XID ${(ourDHCPXID >>> 0).toString(16)}`);
    sendIPPacket(makeDHCPIP(iface, true), makeDHCPRenewRequest(iface), iface);
}
