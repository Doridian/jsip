import { MAC_NONE, MACAddr } from "./ethernet/address";
import { IP_NONE, IPAddr } from "./ethernet/ip/address";
import { IPNet, IPNET_NONE } from "./ethernet/ip/subnet";
import { logDebug } from "./util/log";

export const config: {
    ourIp: IPAddr;
    serverIp: IPAddr;
    gatewayIp: IPAddr;
    ourSubnet: IPNet;
    ourMac: MACAddr;
    mss: number;
    mtu: number;
    sendEth: boolean;
    dnsServerIps: IPAddr[];
    ipDoneCB?: (() => void);
} = {
    dnsServerIps: [],
    gatewayIp: IP_NONE,
    mss: -1,
    mtu: -1,
    ourIp: IP_NONE,
    ourMac: MAC_NONE,
    ourSubnet: IPNET_NONE,
    sendEth: false,
    serverIp: IP_NONE,
};

export function configOut() {
    logDebug(`Our Subnet: ${config.ourSubnet}`);
    logDebug(`Our IP: ${config.ourIp}`);
    logDebug(`Server IP: ${config.serverIp}`);
    logDebug(`Gateway IP: ${config.gatewayIp}`);
}
