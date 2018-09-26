import { EthHdr } from "./ethernet";
import { MACAddr } from "./ethernet_addr";
import { IPAddr } from "./ip_addr";
import { IPNet } from "./ip_net";

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
    console.log(`Our Subnet: ${config.ourSubnet}`);
    console.log(`Our IP: ${config.ourIp}`);
    console.log(`Server IP: ${config.serverIp}`);
    console.log(`Gateway IP: ${config.gatewayIp}`);
}
