import { IInterface } from "../../../../interface/index";
import { VoidCB } from "../../../../util/index";
import { logDebug } from "../../../../util/log";
import { IP_BROADCAST, IP_NONE, IPAddr } from "../../address";
import { IPHdr, IPPROTO } from "../../index";
import { addRoute, flushRoutes, recomputeRoutes } from "../../router";
import { sendIPPacket } from "../../send";
import { IPNet, IPNET_ALL } from "../../subnet";
import { addDNSServer, flushDNSServers } from "../dns/index";
import { UDPPkt } from "../index";
import { udpListen } from "../stack";
import { DHCP_MODE, DHCP_OPTION, DHCPPkt } from "./index";

const dhcpNegotiators = new Map<IInterface, DHCPNegotiator>();

export class DHCPNegotiator {
    private xid: number | undefined;
    private secs: number = 0;
    private iface: IInterface;
    private renewTimer: number | undefined;
    private server: IPAddr = IP_BROADCAST;
    private doneCB: VoidCB | undefined;

    constructor(iface: IInterface, cb?: VoidCB) {
        this.doneCB = cb;
        this.iface = iface;
    }

    public stop() {
        this.stopTimer();
    }

    public negotiate(secs = 0) {
        this.stopTimer();

        if (secs === 0) {
            this.xid = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
            logDebug(`DHCP Initial XID ${(this.xid >>> 0).toString(16)}`);
        } else {
            logDebug(`DHCP Initial retry: secs = ${secs}`);
        }
        this.secs = secs;

        this.renewTimer = setTimeout(() => this.negotiate(secs + 5), 5000);
        sendIPPacket(this.makeDHCPIP(), this.makeDHCPDiscover(), this.iface);
    }

    public renew() {
        this.stopTimer();
        this._renew(0);
    }

    public _handlePacket(dhcp: DHCPPkt) {
        if (dhcp.op !== 2 || dhcp.xid !== this.xid) {
            return;
        }

        this.stopTimer();

        switch (dhcp.options.get(DHCP_OPTION.MODE)![0]) {
            case DHCP_MODE.OFFER:
                logDebug("Got DHCP offer, sending DHCP request...");
                sendIPPacket(this.makeDHCPIP(), this.makeDHCPRequestFromOffer(dhcp), this.iface);
                break;
            case DHCP_MODE.ACK:
                flushRoutes(this.iface);

                const dhcpOptIp = dhcp.options.get(DHCP_OPTION.IP);
                const ourIp = dhcpOptIp ?
                    IPAddr.fromByteArray(dhcpOptIp, 0) :
                    dhcp.yiaddr;

                this.iface.setIP(ourIp);

                let subnet;
                const subnetDHCP = dhcp.options.get(DHCP_OPTION.SUBNET);
                if (subnetDHCP) {
                    subnet = new IPNet(
                        ourIp,
                        subnetDHCP[3] + (subnetDHCP[2] << 8) + (subnetDHCP[1] << 16) + (subnetDHCP[0] << 24),
                    );
                } else {
                    subnet = IPNet.fromIPAndSubnet(ourIp, 32);
                }

                this.iface.setSubnet(subnet);
                recomputeRoutes();

                const dhcpServerRaw = dhcp.options.get(DHCP_OPTION.SERVER);
                this.server = dhcpServerRaw ?
                    IPAddr.fromByteArray(dhcpServerRaw, 0) :
                    dhcp.siaddr;

                const dhcpRouterRaw = dhcp.options.get(DHCP_OPTION.ROUTER);
                if (dhcpRouterRaw) {
                    const router = IPAddr.fromByteArray(dhcpRouterRaw, 0);
                    if (!subnet.contains(router)) {
                        addRoute(IPNet.fromIPAndSubnet(router, 32), IP_NONE, this.iface);
                    }
                    addRoute(IPNET_ALL, router, this.iface);
                }

                const routesRaw = dhcp.options.get(DHCP_OPTION.CLASSLESS_STATIC_ROUTE);
                if (routesRaw) {
                    for (let i = 0; i < routesRaw.byteLength; i++) {
                        const subnetLen = routesRaw[i];
                        const optLen = Math.ceil(subnetLen / 8);

                        i++;
                        const route = IPNet.fromIPAndSubnet(
                            IPAddr.fromPartialByteArray(routesRaw, i, optLen), subnetLen);
                        i += optLen;
                        const ip = IPAddr.fromByteArray(routesRaw, i);
                        i += 3;

                        addRoute(route, ip, this.iface);
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

                this.xid = undefined;

                logDebug(`DHCP TTL: ${ttl}`);
                const ttlHalftime = ((ttl * 1000) / 2) + 1000;
                this.renewTimer = setTimeout(() => this._renew((ttl * 1000) - ttlHalftime), ttlHalftime);

                if (this.doneCB) {
                    this.doneCB();
                    this.doneCB = undefined;
                }
                break;
            case DHCP_MODE.NACK:
                setTimeout(() => this.negotiate(), 0);
                break;
        }
    }

    private stopTimer() {
        if (this.renewTimer !== undefined) {
            clearTimeout(this.renewTimer);
            this.renewTimer = undefined;
        }
    }

    private _renew(renegotiateAfter: number = 0) {
        if (renegotiateAfter) {
            this.renewTimer = setTimeout(() => this.negotiate(), renegotiateAfter);
        }

        this.secs = 0;
        this.xid = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
        logDebug(`DHCP Renew XID ${(this.xid >>> 0).toString(16)}`);
        sendIPPacket(this.makeDHCPIP(true), this.makeDHCPRenewRequest(), this.iface);
    }

    private addDHCPOptions(pkt: DHCPPkt, mode: DHCP_MODE) {
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

    private makeDHCPDiscover() {
        const pkt = new DHCPPkt();
        pkt.xid = this.xid!;
        pkt.secs = this.secs;
        pkt.chaddr = this.iface.getMAC();
        this.addDHCPOptions(pkt, DHCP_MODE.DISCOVER);
        return this.makeDHCPUDP(pkt);
    }

    private makeDHCPRequest(ip: IPAddr) {
        const pkt = new DHCPPkt();
        pkt.xid = this.xid!;
        pkt.secs = this.secs;
        pkt.chaddr = this.iface.getMAC();
        this.addDHCPOptions(pkt, DHCP_MODE.REQUEST);
        pkt.options.set(DHCP_OPTION.IP, ip.toByteArray());
        pkt.options.set(DHCP_OPTION.SERVER, this.server.toByteArray());
        return this.makeDHCPUDP(pkt);
    }

    private makeDHCPRequestFromOffer(offer: DHCPPkt) {
        this.server = offer.siaddr;
        return this.makeDHCPRequest(offer.yiaddr);
    }

    private makeDHCPRenewRequest() {
        return this.makeDHCPRequest(this.iface.getIP());
    }

    private makeDHCPUDP(dhcp: DHCPPkt) {
        const pkt = new UDPPkt();
        pkt.data = dhcp.toBytes();
        pkt.sport = 68;
        pkt.dport = 67;
        return pkt;
    }

    private makeDHCPIP(unicast: boolean = false) {
        const ip = new IPHdr();
        ip.protocol = IPPROTO.UDP;
        if (unicast) {
            ip.saddr = this.iface.getIP();
            ip.daddr = this.server;
        } else {
            ip.saddr = IP_NONE;
            ip.daddr = IP_BROADCAST;
        }
        ip.df = true;
        return ip;
    }
}

function byteArrayToIpAddrs(array: Uint8Array) {
    const res = [];
    for (let i = 0; i < array.byteLength; i += 4) {
        res.push(IPAddr.fromByteArray(array, i));
    }
    return res;
}

udpListen(68, (data: Uint8Array, _: IPHdr, iface: IInterface) => {
    const negotiator = dhcpNegotiators.get(iface);
    if (!negotiator) {
        return;
    }

    const packet = data.buffer;
    const offset = data.byteOffset;

    const dhcp = DHCPPkt.fromPacket(packet, offset);
    negotiator._handlePacket(dhcp);
});

export function addDHCP(iface: IInterface, cb?: VoidCB): DHCPNegotiator {
    removeDHCP(iface);
    const negotiator = new DHCPNegotiator(iface, cb);
    dhcpNegotiators.set(iface, negotiator);
    return negotiator;
}

export function getDHCP(iface: IInterface) {
    return dhcpNegotiators.get(iface);
}

export function removeDHCP(iface: IInterface) {
    const old = getDHCP(iface);
    if (old) {
        dhcpNegotiators.delete(iface);
        old.stop();
    }
}