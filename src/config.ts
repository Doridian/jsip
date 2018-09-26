import { MACAddr } from "./ethernet/address";
import { EthHdr } from "./ethernet/index";
import { IPAddr } from "./ethernet/ip/address";
import { IPNet } from "./ethernet/ip/subnet";
import { logDebug } from "./util/log";

export const config: {
    ourIp?: IPAddr;
    serverIp?: IPAddr;
    gatewayIp?: IPAddr;
    ourSubnet?: IPNet;
    ourMac?: MACAddr;
    mss: number;
    mtu: number;
    sendEth: boolean;
    ethBcastHdr?: EthHdr;
    dnsServerIps: IPAddr[];
    ipDoneCB?: (() => void);
    ws?: WebSocket;
} = {
    dnsServerIps: [],
    mss: -1,
    mtu: -1,
    sendEth: false,
};

export function configOut() {
    logDebug(`Our Subnet: ${config.ourSubnet}`);
    logDebug(`Our IP: ${config.ourIp}`);
    logDebug(`Server IP: ${config.serverIp}`);
    logDebug(`Gateway IP: ${config.gatewayIp}`);
}
