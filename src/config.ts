import { IP_NONE } from "./ethernet/ip/address";
import { getRoutes } from "./ethernet/ip/router";
import { getDNSServers } from "./ethernet/ip/udp/dns/index";
import { INTERFACE_NONE } from "./interface";
import { logDebug } from "./util/log";

export function configOut() {
    // logDebug(`Our IP: ${config.ourIp}`);
    getRoutes().forEach((route) => {
        let routeStr = `Route to ${route.subnet}`;
        if (route.iface !== INTERFACE_NONE) {
            routeStr += ` on ${route.iface.getName()}`;
        }
        if (route.router !== IP_NONE) {
            routeStr += ` gw ${route.router}`;
        }
        logDebug(routeStr);
    });
    logDebug(`DNS servers: ${getDNSServers().join(", ")}`);
}
