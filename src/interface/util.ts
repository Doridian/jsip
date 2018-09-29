import { flushRoutes, recomputeRoutes } from "../ethernet/ip/router";
import { removeDHCP } from "../ethernet/ip/udp/dhcp/stack";
import { flushDNSServers } from "../ethernet/ip/udp/dns/index";
import { IInterface } from "./index";
import { addInterface, deleteInterface } from "./stack";

export function addInterfaceEasy(iface: IInterface) {
    addInterface(iface);
    recomputeRoutes();
}

export function deleteInterfaceEasy(iface: IInterface) {
    deleteInterface(iface);
    removeDHCP(iface);
    flushRoutes(iface);
    flushDNSServers(iface);
}
