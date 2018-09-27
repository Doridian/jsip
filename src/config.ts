import { MAC_NONE, MACAddr } from "./ethernet/address";
import { IP_NONE, IPAddr } from "./ethernet/ip/address";
import { getRoutes } from "./ethernet/ip/router";
import { logDebug } from "./util/log";

export const config: {
    dnsServerIps: IPAddr[];
    enableEthernet: boolean;
    mtu: number;
    ourIp: IPAddr;
    ourMac: MACAddr;
} = {
    dnsServerIps: [],
    enableEthernet: false,
    mtu: -1,
    ourIp: IP_NONE,
    ourMac: MAC_NONE,
};

export function configOut() {
    logDebug(`Our IP: ${config.ourIp}`);
    getRoutes().forEach((route) => {
        logDebug(`Route to ${route.subnet} via ${(route.router === IP_NONE) ? "direct" : route.router}`);
    });
}
