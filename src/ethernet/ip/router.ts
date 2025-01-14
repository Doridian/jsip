import { IInterface } from "../../interface/index.js";
import { getLoopbackInterface } from "../../interface/loopback.js";
import { getInterfaces } from "../../interface/stack.js";
import { IPAddr } from "./address.js";
import { IPNet, IPNET_BROADCAST, IPNET_LINK_LOCAL, IPNET_MULTICAST } from "./subnet.js";

export const enum Metric {
    Core = 0,
    CoreLocal = 1,
    MinUserConfigurable = 5,

    Local = 10,
    StaticDefault = 50,
    DHCPDefault = 100,
}

export interface IPRoute {
    readonly metric: number;
    readonly subnet: IPNet;
    readonly router?: IPAddr;
    readonly iface?: IInterface;
    readonly src?: IPAddr;
}

function routeEquals(routeA: IPRoute, routeB: IPRoute) {
    return routeA.metric === routeB.metric &&
            routeA.router?.equals(routeB.router) &&
            routeA.iface === routeB.iface &&
            routeA.src?.equals(routeB.src);
}

const staticRoutes: IPRoute[] = sortRoutes([
    {
        subnet: IPNET_LINK_LOCAL,
        metric: Metric.Core,
    },
    {
        subnet: IPNET_BROADCAST,
        metric: Metric.Core,
    },
    {
        subnet: IPNET_MULTICAST,
        metric: Metric.Core,
    },
]);

function sortRoutes(toSort: IPRoute[]): IPRoute[] {
    return toSort.sort((a, b) => {
        const res = b.subnet.compareTo(a.subnet);
        if (res === 0) {
            return b.metric - a.metric;
        }
        return res;
    });
}

const routeCache = new Map<number, IPRoute | null>();
let routes: IPRoute[] = [];

export function getRoute(ip: IPAddr, _?: IInterface): IPRoute | null {
    if (routes.length < 1) {
        recomputeRoutes();
    }

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
    if (routes.length < 1) {
        recomputeRoutes();
    }

    return routes.slice(0);
}

export function clearRoutesFor(iface: IInterface) {
    let needCompute = false;
    for (const key of Array.from(staticRoutes.keys())) {
        if (routes[key] && routes[key].iface === iface) {
            needCompute = true;
            staticRoutes.splice(key, 1);
        }
    }

    if (!needCompute) {
        return;
    }
    recomputeRoutes();
}

export function addRoute(route: IPRoute) {
    removeRoute(route);
    staticRoutes.push(route);
    recomputeRoutes();
}

export function removeRoute(route: IPRoute) {
    const idx = staticRoutes.findIndex((value) => routeEquals(route, value) && value.metric >= Metric.MinUserConfigurable);

    if (idx >= 0) {
        staticRoutes.splice(idx, 1);
        recomputeRoutes();
    }
}

export function recomputeRoutes() {
    routes = staticRoutes.slice(0);
    for (const iface of getInterfaces()) {
        const subnet = iface.getSubnet();
        const src = iface.getIP();
        const metric = Metric.CoreLocal;

        if (subnet) {
            routes.push({ subnet, src, metric, iface });
        }

        if (src) {
            routes.push({ src, metric, iface: getLoopbackInterface(), subnet: IPNet.fromIPAndSubnet(src, 32) });
        }
    }
    routes = sortRoutes(routes);
    routeCache.clear();
}

export function reversePathCheck(iface: IInterface, src: IPAddr): boolean {
    const route = getRoute(src, iface);
    if (!route) {
        return false;
    }
    return !route.iface || route.iface === iface;
}
