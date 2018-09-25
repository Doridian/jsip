import { MACAddr, EthHdr } from "./ethernet";
import { IPAddr, IPNet } from "./ip";

export const config: {
    ourIp: IPAddr|undefined;
    serverIp: IPAddr|undefined;
    gatewayIp: IPAddr|undefined;
    ourSubnet: IPNet|undefined;
    ourMac: MACAddr|undefined;
    mtu: number;
    mss: number;
    sendEth: boolean;
    ethBcastHdr: EthHdr|undefined;
    dnsServerIps: IPAddr[];
    ipDoneCB: (() => void)|undefined;
    ws: WebSocket|undefined;
} = {
    ourIp: undefined,
    serverIp: undefined,
    gatewayIp: undefined,
    ourSubnet: undefined,
    ourMac: undefined,
    mtu: -1,
    mss: -1,
    sendEth: false,
    ethBcastHdr: undefined,
    dnsServerIps: [],
    ipDoneCB: undefined,
    ws: undefined,
};

export function configOut() {
	console.log(`Our Subnet: ${config.ourSubnet}`);
	console.log(`Our IP: ${config.ourIp}`);
	console.log(`Server IP: ${config.serverIp}`);
	console.log(`Gateway IP: ${config.gatewayIp}`);
}