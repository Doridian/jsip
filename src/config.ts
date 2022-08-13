import { getRoutes } from "./ethernet/ip/router.js";
import { getDNSServers } from "./ethernet/ip/udp/dns/stack.js";
import { getInterfaces } from "./interface/stack.js";
import { logDebug } from "./util/log.js";

export function configOut() {
    const ifaces = getInterfaces();
    const ifacesStr = ifaces.map((iface) => {
        return `${iface.getName()} mtu ${iface.getMTU()} address ${iface.getIP()}` +
                    ` subnet ${iface.getSubnet()} hwaddr ${iface.getMAC()}`;
    });
    logDebug(`INTERFACE TABLE\n${ifacesStr.join("\n")}`);
    const routesStr = getRoutes().map((route) => {
        let routeStr = `${route.subnet}`;
        let validRoute = false;
        if (route.iface) {
            routeStr += ` on ${route.iface.getName()}`;
            validRoute = true;
        }
        if (route.src) {
            routeStr += ` src ${route.src}`;
        }
        if (route.router) {
            routeStr += ` gw ${route.router}`;
            validRoute = true;
        } else {
            routeStr += " link-local";
        }
        if (!validRoute) {
            routeStr += " virtual";
        }
        return routeStr;
    });
    logDebug(`ROUTE TABLE\n${routesStr.join("\n")}`);
    const dnsServersStr = ifaces.map((iface) => {
        const ifaceDNS = getDNSServers(iface);
        return ifaceDNS.map((dns) => `${dns} on ${iface.getName()}`).join("\n");
    });
    logDebug(`DNS SERVERS\n${dnsServersStr.filter((str) => str.length > 0).join("\n")}`);
}
