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
};
