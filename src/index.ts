import { enableARP } from "./ethernet/arp/stack";
import { enableIP } from "./ethernet/ip/stack";
import { enableICMP } from "./ethernet/ip/icmp/stack";
import { enableUDP, enableUDPEcho } from "./ethernet/ip/udp/stack";
import { enableTCP, enableTCPEcho } from "./ethernet/ip/tcp/stack";
import { enableDHCP } from "./ethernet/ip/udp/dhcp/stack";
import { enableDNS } from "./ethernet/ip/udp/dns/stack";
import { addLoopback } from "./interface/loopback";

export { Interface, IInterface } from "./interface";

export function initialize() {
    addLoopback();

    enableARP();
    enableIP();

    enableICMP();
    enableUDP();
    enableTCP();

    enableDHCP();
    enableDNS();
}

export function enableEcho() {
    enableTCPEcho();
    enableUDPEcho();
}
