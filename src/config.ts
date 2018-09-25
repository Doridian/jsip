import { MACAddr, EthHdr } from "./ethernet";
import { IPAddr, IPNet } from "./ip";

export const config: {
    ourIp?: IPAddr;
    serverIp?: IPAddr;
    gatewayIp?: IPAddr;
    ourSubnet?: IPNet;
    ourMac?: MACAddr;
    mtu: number;
    mss: number;
    sendEth: boolean;
    ethBcastHdr?: EthHdr;
    dnsServerIps: IPAddr[];
    ipDoneCB?: (() => void);
    ws?: WebSocket;
} = {
    mtu: -1,
    mss: -1,
    sendEth: false,
    dnsServerIps: [],
};

export function configOut() {
	console.log(`Our Subnet: ${config.ourSubnet}`);
	console.log(`Our IP: ${config.ourIp}`);
	console.log(`Server IP: ${config.serverIp}`);
	console.log(`Gateway IP: ${config.gatewayIp}`);
}
