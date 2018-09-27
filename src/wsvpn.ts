import { config, configOut } from "./config";
import { MACAddr } from "./ethernet/address";
import { IP_NONE } from "./ethernet/ip/address";
import { addRoute, resetRoutes } from "./ethernet/ip/router";
import { IPNet, IPNET_ALL } from "./ethernet/ip/subnet";
import { dhcpNegotiate } from "./ethernet/ip/udp/dhcp/index";
import { addDNSServer, flushDNSServers } from "./ethernet/ip/udp/dns/index";
import { randomByte, VoidCB } from "./util/index";
import { logDebug } from "./util/log";
import { handlePacket } from "./util/packet";

let ws: WebSocket | undefined;

export function sendRaw(msg: ArrayBuffer) {
    ws!.send(msg);
}

export function connectWSVPN(url: string, cb: VoidCB) {
    logDebug(`Connecting to WSVPN: ${url}`);

    ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";

    ws.onmessage = (msg) => {
        const data = msg.data;
        if (typeof data !== "string") {
            handlePacket(data);
            return;
        }

        handleInit(data, cb);
    };
}

function handleInit(data: string, cb: VoidCB) {
    let needDHCP = false;
    // 1|init|TUN|192.168.3.1/24|1280
    const spl = data.split("|");

    resetRoutes();
    flushDNSServers();

    switch (spl[2]) {
        case "TAP":
            config.enableEthernet = true;
        case "TUN":
            const subnet = IPNet.fromString(spl[3]);
            config.ourIp = subnet.ip;
            addRoute(subnet, IP_NONE);
            addRoute(IPNET_ALL, subnet.getAddress(0));
            addDNSServer(subnet.getAddress(0));
            break;
        case "TAP_NOCONF":
            config.enableEthernet = true;
            needDHCP = true;
            break;
    }

    config.mtu = parseInt(spl[4], 10);

    logDebug(`Mode: ${spl[2]}`);

    logDebug(`Link-MTU: ${config.mtu}`);

    if (config.enableEthernet) {
        config.ourMac = MACAddr.fromBytes(0x0A, randomByte(), randomByte(), randomByte(), randomByte(), randomByte());
        logDebug(`Our MAC: ${config.ourMac}`);
    }

    configOut();

    if (needDHCP) {
        logDebug("Starting DHCP procedure...");
        dhcpNegotiate(cb);
    } else if (cb) {
        setTimeout(cb, 0);
    }
}
