import { IP_NONE, IPAddr } from "./address";
import { IPNet, IPNET_BROADCAST, IPNET_NONE, IPNETS_MULTICAST } from "./subnet";

interface IPRoute {
    router: IPAddr;
    subnet: IPNet;
}

const IPNET_LINK_LOCAL = IPNet.fromString("169.254.0.0/16");

const staticRoutes: IPRoute[] = [
    {
        router: IP_NONE,
        subnet: IPNET_NONE,
    },
    {
        router: IP_NONE,
        subnet: IPNET_LINK_LOCAL,
    },
    {
        router: IP_NONE,
        subnet: IPNET_BROADCAST,
    },
];

IPNETS_MULTICAST.forEach((net) => {
    staticRoutes.push({
        router: IP_NONE,
        subnet: net,
    });
});

function sortRoutes(toSort: IPRoute[]): IPRoute[] {
    return toSort.sort((a, b) => {
        return b.subnet.bitmask - a.subnet.bitmask;
    });
}

let routes: IPRoute[];

export function getRoute(ip: IPAddr): IPAddr | undefined {
    for (const route of routes) {
        if (route.subnet.contains(ip)) {
            return route.router;
        }
    }

    return undefined;
}

export function resetRoutes() {
    routes = sortRoutes(staticRoutes.slice(0));
}

export function addRoute(subnet: IPNet, router: IPAddr) {
    routes.push({ router, subnet });
    routes = sortRoutes(routes);
}

export function delRoute(subnet: IPNet) {
    const idx = routes.findIndex((value) => value.subnet.equals(subnet));
    if (idx >= 0) {
        routes.splice(idx, 1);
    }
}

resetRoutes();
