import { MACAddr, EthHdr } from "./ethernet";
import { IPAddr, IPNet } from "./ip";

export let ourIp: IPAddr;
export let serverIp: IPAddr;
export let gatewayIp: IPAddr;
export let ourSubnet: IPNet;
export let ourMac: MACAddr;
export let mtu: Number;
export let mss: Number;
export let sendEth: boolean;
export let ethBcastHdr: EthHdr;
export let dnsServerIps: IPAddr[];
