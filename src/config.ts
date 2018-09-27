import { MAC_NONE, MACAddr } from "./ethernet/address";
import { IP_NONE, IPAddr } from "./ethernet/ip/address";
import { logDebug } from "./util/log";

export const config: {
    dnsServerIps: IPAddr[];
    enableEthernet: boolean;
    mtu: number;
    ourIp: IPAddr;
    ourMac: MACAddr;
} = {
    dnsServerIps: [],
    enableEthernet: false,
    mtu: -1,
    ourIp: IP_NONE,
    ourMac: MAC_NONE,
};

export function configOut() {
    logDebug(`Our IP: ${config.ourIp}`);
}
