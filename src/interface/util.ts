import { flushRoutes, recomputeRoutes } from "../ethernet/ip/router.js";
import { removeDHCP } from "../ethernet/ip/udp/dhcp/stack.js";
import { flushDNSServers } from "../ethernet/ip/udp/dns/index.js";
import { IInterface } from "./index.js";
import { addInterface, deleteInterface } from "./stack.js";

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
