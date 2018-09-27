import { MAC_NONE, MACAddr } from "./ethernet/address";
import { IP_NONE, IPAddr } from "./ethernet/ip/address";
import { getRoutes } from "./ethernet/ip/router";
import { getDNSServers } from "./ethernet/ip/udp/dns/index";
import { logDebug } from "./util/log";

export const config: {
    enableEthernet: boolean;
    mtu: number;
    ourIp: IPAddr;
    ourMac: MACAddr;
} = {
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
    logDebug(`DNS servers: ${getDNSServers().join(", ")}`);
}
