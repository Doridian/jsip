import { MAC_NONE, MACAddr } from "./ethernet/address";
import { IP_NONE, IPAddr } from "./ethernet/ip/address";
import { IPNet, IPNET_NONE } from "./ethernet/ip/subnet";
import { logDebug } from "./util/log";

export const config: {
    dnsServerIps: IPAddr[];
    enableEthernet: boolean;
    gatewayIp: IPAddr;
    mtu: number;
    ourIp: IPAddr;
    ourMac: MACAddr;
    ourSubnet: IPNet;
    serverIp: IPAddr;
} = {
    dnsServerIps: [],
    enableEthernet: false,
    gatewayIp: IP_NONE,
    mtu: -1,
    ourIp: IP_NONE,
    ourMac: MAC_NONE,
    ourSubnet: IPNET_NONE,
    serverIp: IP_NONE,
};

export function configOut() {
    logDebug(`Our Subnet: ${config.ourSubnet}`);
    logDebug(`Our IP: ${config.ourIp}`);
    logDebug(`Server IP: ${config.serverIp}`);
    logDebug(`Gateway IP: ${config.gatewayIp}`);
}
