import { config, configOut } from "../../../../config";
import { VoidCB } from "../../../../util/index";
import { logDebug } from "../../../../util/log";
import { MACAddr } from "../../../address";
import { ARP_HLEN, ARP_HTYPE } from "../../../arp/index";
import { IP_BROADCAST, IP_NONE, IPAddr } from "../../address";
import { IPHdr, IPPROTO } from "../../index";
import { addRoute, resetRoutes } from "../../router";
import { sendIPPacket } from "../../send";
import { IPNet, IPNET_ALL } from "../../subnet";
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
            logDebug("Invalid DHCP magic");
            return null;
        }

        dhcp.options = {};

        let i = DHCP_MAGIC_OFFSET + 4;
        let gotEnd = false;
        while (i < data.byteLength) {
            const optId = data[i];
            if (optId === 0xFF) {
                gotEnd = true;
                break;
            }

            const optLen = data[i + 1];
            dhcp.options[optId] = new Uint8Array(packet, offset + i + 2, optLen);
            i += optLen + 2;
        }

        if (!gotEnd) {
            logDebug("Invalid DHCP end");
            return null;
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
    public chaddr = config.ourMac;
    public options: { [key: string]: Uint8Array } = {};

    public getFullLength() {
        let optLen = 1; // 0xFF always needed
        Object.keys(this.options).forEach((optK) => {
            const opt = this.options[optK];
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
        Object.keys(this.options).forEach((optId) => {
            const opt = this.options[optId];
            const optLen = opt.byteLength;
            packet[optPos] = parseInt(optId, 10);
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

function makeDHCPDiscover() {
    const pkt = new DHCPPkt();
    pkt.options[DHCP_OPTION.MODE] = new Uint8Array([DHCP_MODE.DISCOVER]);
    pkt.options[DHCP_OPTION.OPTIONS] = new Uint8Array([
        DHCP_OPTION.ROUTER,
        DHCP_OPTION.SUBNET,
        DHCP_OPTION.DNS,
        DHCP_OPTION.LEASETIME,
        DHCP_OPTION.SERVER,
        DHCP_OPTION.IP,
    ]);
    return makeDHCPUDP(pkt);
}

function makeDHCPRequest(offer: DHCPPkt) {
    const pkt = new DHCPPkt();
    pkt.options[DHCP_OPTION.MODE] = new Uint8Array([DHCP_MODE.REQUEST]);
    pkt.options[DHCP_OPTION.IP] = offer.yiaddr.toByteArray();
    pkt.options[DHCP_OPTION.SERVER] = offer.siaddr.toByteArray();
    return makeDHCPUDP(pkt);
}

function makeDHCPRenewRequest() {
    const pkt = new DHCPPkt();
    pkt.options[DHCP_OPTION.MODE] = new Uint8Array([DHCP_MODE.REQUEST]);
    pkt.options[DHCP_OPTION.IP] = config.ourIp.toByteArray();
    pkt.options[DHCP_OPTION.SERVER] = dhcpServer.toByteArray();
    return makeDHCPUDP(pkt);
}

function makeDHCPUDP(dhcp: DHCPPkt) {
    const pkt = new UDPPkt();
    pkt.data = dhcp.toBytes();
    pkt.sport = 68;
    pkt.dport = 67;
    return pkt;
}

function makeDHCPIP(unicast: boolean = false) {
    const ip = new IPHdr();
    ip.protocol = IPPROTO.UDP;
    if (unicast) {
        ip.saddr = config.ourIp;
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

udpListen(68, (data: Uint8Array) => {
    const packet = data.buffer;
    const offset = data.byteOffset;

    const dhcp = DHCPPkt.fromPacket(packet, offset);
    if (!dhcp || dhcp.op !== 2) {
        return;
    }

    if (dhcp.xid !== ourDHCPXID) {
        return;
    }

    if (dhcpRenewTimer !== undefined) {
        clearTimeout(dhcpRenewTimer);
        dhcpRenewTimer = undefined;
    }

    switch (dhcp.options[DHCP_OPTION.MODE][0]) {
        case DHCP_MODE.OFFER:
            logDebug("Got DHCP offer, sending DHCP request...");
            sendIPPacket(makeDHCPIP(), makeDHCPRequest(dhcp));
            break;
        case DHCP_MODE.ACK:
            resetRoutes();

            config.ourIp = dhcp.options[DHCP_OPTION.IP] ?
                IPAddr.fromByteArray(dhcp.options[DHCP_OPTION.IP], 0) :
                dhcp.yiaddr;

            let subnet;
            if (dhcp.options[DHCP_OPTION.SUBNET]) {
                const subnetDHCP = dhcp.options[DHCP_OPTION.SUBNET];
                subnet = new IPNet(
                    config.ourIp,
                    subnetDHCP[3] + (subnetDHCP[2] << 8) + (subnetDHCP[1] << 16) + (subnetDHCP[0] << 24),
                );
            } else {
                subnet = IPNet.fromString(`${config.ourIp}/32`);
            }

            addRoute(subnet, IP_NONE);

            dhcpServer = dhcp.options[DHCP_OPTION.SERVER] ?
                IPAddr.fromByteArray(dhcp.options[DHCP_OPTION.SERVER], 0) :
                dhcp.siaddr;

            const defgw = dhcp.options[DHCP_OPTION.ROUTER] ?
                IPAddr.fromByteArray(dhcp.options[DHCP_OPTION.ROUTER], 0) :
                undefined;

            config.dnsServerIps = dhcp.options[DHCP_OPTION.DNS] ?
                byteArrayToIpAddrs(dhcp.options[DHCP_OPTION.DNS]) :
                [];

            if (defgw) {
                addRoute(IPNET_ALL, defgw);
            }

            let ttl;
            if (dhcp.options[DHCP_OPTION.LEASETIME]) {
                const rawTtl = dhcp.options[DHCP_OPTION.LEASETIME];
                ttl = (rawTtl[3] + (rawTtl[2] << 8) + (rawTtl[1] << 16) + (rawTtl[0] << 24)) >>> 0;
            } else {
                ttl = 300;
            }

            if (dhcpInInitialConfig) {
                dhcpInInitialConfig = false;
                configOut();
            }
            ourDHCPXID = undefined;

            logDebug(`DHCP TTL: ${ttl}`);
            const ttlHalftime = ((ttl * 1000) / 2) + 1000;
            dhcpRenewTimer = setTimeout(dhcpRenew, ttlHalftime, (ttl * 1000) - ttlHalftime);

            if (dhcpDoneCB) {
                dhcpDoneCB();
                dhcpDoneCB = undefined;
            }
            break;
        case DHCP_MODE.NACK:
            setTimeout(() => dhcpNegotiate(), 0);
            break;
    }
});

export function dhcpNegotiate(cb?: VoidCB, secs = 0) {
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

    dhcpRenewTimer = setTimeout(() => dhcpNegotiate(undefined, secs + 5), 5000);
    sendIPPacket(makeDHCPIP(), makeDHCPDiscover());
}

function dhcpRenew(renegotiateAfter: number = 0) {
    if (renegotiateAfter) {
        dhcpRenewTimer = setTimeout(() => dhcpNegotiate(), renegotiateAfter);
    }

    ourDHCPSecs = 0;
    ourDHCPXID = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
    logDebug(`DHCP Renew XID ${(ourDHCPXID >>> 0).toString(16)}`);
    sendIPPacket(makeDHCPIP(true), makeDHCPRenewRequest());
}
