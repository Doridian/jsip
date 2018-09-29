import { IP_NONE } from "./ethernet/ip/address";
import { getRoutes } from "./ethernet/ip/router";
import { getDNSServers } from "./ethernet/ip/udp/dns/index";
import { INTERFACE_NONE } from "./interface/none";
import { getInterfaces } from "./interface/stack";
import { logDebug } from "./util/log";

export function configOut() {
    const ifaces = getInterfaces().map((iface) => {
        return `${iface.getName()} mtu ${iface.getMTU()} address ${iface.getIP()}` +
                    ` subnet ${iface.getSubnet()} hwaddr ${iface.getMAC()}`;
    });
    logDebug(`INTERFACE TABLE\n${ifaces.join("\n")}`);
    const routes = getRoutes().map((route) => {
        let routeStr = `${route.subnet}`;
        let validRoute = false;
        if (route.iface !== INTERFACE_NONE) {
            routeStr += ` on ${route.iface.getName()}`;
            validRoute = true;
        }
        if (route.router !== IP_NONE) {
            routeStr += ` gw ${route.router}`;
            validRoute = true;
        }
        if (!validRoute) {
            routeStr += " link-local";
        }
        return routeStr;
    });
    logDebug(`ROUTE TABLE\n${routes.join("\n")}`);
    logDebug(`DNS SERVERS\n${getDNSServers().join("\n")}`);
}
