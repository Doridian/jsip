import { IInterface } from "../../interface/index.js";
import { INTERFACE_LOOPBACK } from "../../interface/loopback.js";
import { INTERFACE_NONE } from "../../interface/none.js";
import { getInterfaces } from "../../interface/stack.js";
import { IP_NONE, IPAddr } from "./address.js";
import { IPNet, IPNET_BROADCAST, IPNET_LINK_LOCAL, IPNET_MULTICAST, IPNET_NONE } from "./subnet.js";

interface IPRoute {
    router: IPAddr;
    iface: IInterface;
    src: IPAddr;
    subnet: IPNet;
}

const staticRoutes: IPRoute[] = sortRoutes([
    {
        iface: INTERFACE_NONE,
        router: IP_NONE,
        src: IP_NONE,
        subnet: IPNET_NONE,
    },
    {
        iface: INTERFACE_NONE,
        router: IP_NONE,
        src: IP_NONE,
        subnet: IPNET_LINK_LOCAL,
    },
    {
        iface: INTERFACE_NONE,
        router: IP_NONE,
        src: IP_NONE,
        subnet: IPNET_BROADCAST,
    },
    {
        iface: INTERFACE_NONE,
        router: IP_NONE,
        src: IP_NONE,
        subnet: IPNET_MULTICAST,
    },
]);

function sortRoutes(toSort: IPRoute[]): IPRoute[] {
    return toSort.sort((a, b) => {
        return b.subnet.compareTo(a.subnet);
    });
}

const routeCache = new Map<number, IPRoute | null>();
let routes: IPRoute[];

export function getRoute(ip: IPAddr, _: IInterface): IPRoute | null {
    const ipKey = ip.toInt32();
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

export function flushRoutes(iface: IInterface) {
    let needCompute = false;
    for (const key of Array.from(staticRoutes.keys())) {
        if (routes[key].iface === iface) {
            needCompute = true;
            staticRoutes.splice(key, 1);
        }
    }

    if (!needCompute) {
        return;
    }
    recomputeRoutes();
}

export function addRoute(subnet: IPNet, router: IPAddr, iface: IInterface, src: IPAddr = IP_NONE) {
    removeRoute(subnet);
    staticRoutes.push({ router, subnet, iface, src });
    recomputeRoutes();
}

export function removeRoute(subnet: IPNet) {
    const idx = staticRoutes.findIndex((value) => value.subnet.equals(subnet));
    if (idx >= 0) {
        staticRoutes.splice(idx, 1);
        recomputeRoutes();
    }
}

export function recomputeRoutes() {
    routes = staticRoutes.slice(0);
    for (const iface of getInterfaces()) {
        routes.push({ router: IP_NONE, iface, subnet: iface.getSubnet(), src: IP_NONE });
        const ip = iface.getIP();
        routes.push({ router: IP_NONE, iface: INTERFACE_LOOPBACK, subnet: IPNet.fromIPAndSubnet(ip, 32), src: ip });
    }
    routes = sortRoutes(routes);
    routeCache.clear();
}

export function reversePathCheck(iface: IInterface, src: IPAddr): boolean {
    const route = getRoute(src, iface);
    if (!route) {
        return false;
    }
    return route.iface === INTERFACE_NONE || route.iface === iface;
}

routes = staticRoutes.slice(0);

recomputeRoutes();
