import { config, configOut } from "./config";
import { MACAddr } from "./ethernet/address";
import { IP_NONE } from "./ethernet/ip/address";
import { handleIP } from "./ethernet/ip/stack";
import { IPNet, IPNET_NONE } from "./ethernet/ip/subnet";
import { dhcpNegotiate } from "./ethernet/ip/udp/dhcp/index";
import { handleEthernet } from "./ethernet/stack";
import { randomByte, VoidCB } from "./util/index";
import { logDebug } from "./util/log";

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
            if (config.enableEthernet) {
                handleEthernet(data);
            } else {
                handleIP(data);
            }
            return;
        }

        handleInit(data, cb);
    };
}

function handleInit(data: string, cb: VoidCB) {
    let needDHCP = false;
    // 1|init|TUN|192.168.3.1/24|1280
    const spl = data.split("|");

    switch (spl[2]) {
        case "TAP":
            config.enableEthernet = true;
        case "TUN":
            config.ourSubnet = IPNet.fromString(spl[3]);
            config.serverIp = config.ourSubnet.getAddress(0);
            break;
        case "TAP_NOCONF":
            config.enableEthernet = true;
            config.ourSubnet = IPNET_NONE;
            config.serverIp = IP_NONE;
            needDHCP = true;
            break;
    }

    config.mtu = parseInt(spl[4], 10);

    logDebug(`Mode: ${spl[2]}`);

    logDebug(`Link-MTU: ${config.mtu}`);

    config.mss = config.mtu - 40;

    if (config.enableEthernet) {
        config.ourMac = MACAddr.fromBytes(0x0A, randomByte(), randomByte(), randomByte(), randomByte(), randomByte());
        logDebug(`Our MAC: ${config.ourMac}`);
    }

    config.ourIp = config.ourSubnet.ip;
    config.gatewayIp = config.serverIp;
    config.dnsServerIps = [config.gatewayIp];
    configOut();

    if (needDHCP) {
        logDebug("Starting DHCP procedure...");
        dhcpNegotiate(0, cb);
    } else if (cb) {
        setTimeout(cb, 0);
    }
}
