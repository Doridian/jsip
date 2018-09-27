import { IP_NONE, IPAddr } from "./address";
import { IPNet, IPNET_BROADCAST, IPNET_LINK_LOCAL, IPNET_NONE, IPNETS_MULTICAST } from "./subnet";

interface IPRoute {
    router: IPAddr;
    subnet: IPNet;
}

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
        return b.subnet.compareTo(a.subnet);
    });
}

let routeCache: { [key: string]: IPAddr | null } = {};
let routes: IPRoute[];

export function getRoute(ip: IPAddr): IPAddr | null {
    const ipStr = ip.toString();
    const cache = routeCache[ipStr];
    if (cache !== undefined) {
        return cache;
    }

    let res = null;
    for (const route of routes) {
        if (route.subnet.contains(ip)) {
            res = route.router;
            break;
        }
    }

    routeCache[ipStr] = res;
    return res;
}

export function getRoutes() {
    return routes.slice(0);
}

export function resetRoutes() {
    routes = sortRoutes(staticRoutes.slice(0));
    routeCache = {};
}

export function addRoute(subnet: IPNet, router: IPAddr) {
    routes.push({ router, subnet });
    routes = sortRoutes(routes);
    routeCache = {};
}

export function delRoute(subnet: IPNet) {
    const idx = routes.findIndex((value) => value.subnet.equals(subnet));
    if (idx >= 0) {
        routes.splice(idx, 1);
    }
    routeCache = {};
}

resetRoutes();
