import { IInterface, INTERFACE_LOOPBACK, INTERFACE_NONE } from "../../interface";
import { IP_NONE, IPAddr } from "./address";
import { IPNet, IPNET_BROADCAST, IPNET_LINK_LOCAL, IPNET_LOOPBACK, IPNET_NONE } from "./subnet";

interface IPRoute {
    router: IPAddr;
    iface: IInterface;
    subnet: IPNet;
}

const staticRoutes: IPRoute[] = [
    {
        iface: INTERFACE_NONE,
        router: IP_NONE,
        subnet: IPNET_NONE,
    },
    {
        iface: INTERFACE_NONE,
        router: IP_NONE,
        subnet: IPNET_LINK_LOCAL,
    },
    {
        iface: INTERFACE_NONE,
        router: IP_NONE,
        subnet: IPNET_BROADCAST,
    },
    {
        iface: INTERFACE_LOOPBACK,
        router: IP_NONE,
        subnet: IPNET_LOOPBACK,
    },
];

function sortRoutes(toSort: IPRoute[]): IPRoute[] {
    return toSort.sort((a, b) => {
        return b.subnet.compareTo(a.subnet);
    });
}

const routeCache = new Map<number, IPRoute | null>();
let routes: IPRoute[];

export function getRoute(ip: IPAddr, _: IInterface): IPRoute | null {
    const ipKey = ip.toInt();
    const cache = routeCache.get(ipKey);
    if (cache !== undefined) {
        return cache;
    }

    let res = null;
    for (const route of routes) {
        if (route.subnet.contains(ip)) {
            res = route;
            break;
        }
    }

    routeCache.set(ipKey, res);
    return res;
}

export function getRoutes() {
    return routes.slice(0);
}

export function flushRoutes() {
    routes = sortRoutes(staticRoutes.slice(0));
    routeCache.clear();
}

export function addRoute(subnet: IPNet, router: IPAddr, iface: IInterface) {
    removeRoute(subnet);
    routes.push({ router, subnet, iface });
    routes = sortRoutes(routes);
    routeCache.clear();
}

export function removeRoute(subnet: IPNet) {
    const idx = routes.findIndex((value) => value.subnet.equals(subnet));
    if (idx >= 0) {
        routes.splice(idx, 1);
        routeCache.clear();
    }
}

flushRoutes();
