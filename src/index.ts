import { enableARP } from "./ethernet/arp/stack.js";
import { enableIP } from "./ethernet/ip/stack.js";
import { enableICMP } from "./ethernet/ip/icmp/stack.js";
import { enableUDP, enableUDPEcho } from "./ethernet/ip/udp/stack.js";
import { enableTCP, enableTCPEcho } from "./ethernet/ip/tcp/stack.js";
import { enableDHCP } from "./ethernet/ip/udp/dhcp/stack.js";
import { enableDNS } from "./ethernet/ip/udp/dns/stack.js";
import { addLoopback } from "./interface/loopback.js";

export { Interface, IInterface } from "./interface/index.js";

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
