import { config, configOut } from "./config";
import { dhcpNegotiate } from "./dhcp";
import { ETH_TYPE, EthHdr } from "./ethernet";
import { MAC_BROADCAST, MACAddr } from "./ethernet_addr";
import { handleEthernet } from "./ethernet_stack";
import { httpGet } from "./http";
import { IPNet } from "./ip_net";
import { handleIP } from "./ip_stack";
import { randomByte } from "./util";

type VoidCB = () => void;

export function workerMain(cb: VoidCB) {
    if (document.location.protocol === "file:") {
        _workerMain("wss://doridian.net/ws", cb);
        return;
    }

    const proto = (document.location.protocol === "http:") ? "ws:" : "wss:";
    _workerMain(`${proto}//${document.location.host}/ws`, cb);
}

function handleInit(data: string, cb: VoidCB) {
    let needDHCP = false;
    // 1|init|TUN|192.168.3.1/24|1280
    const spl = data.split("|");

    switch (spl[2]) {
        case "TAP":
            config.sendEth = true;
        case "TUN":
            config.ourSubnet = IPNet.fromString(spl[3]);
            config.serverIp = config.ourSubnet.getAddress(0);
            break;
        case "TAP_NOCONF":
            config.sendEth = true;
            config.ourSubnet = undefined;
            config.serverIp = undefined;
            needDHCP = true;
            break;
    }

    config.mtu = parseInt(spl[4], 10);

    console.log(`Mode: ${spl[2]}`);

    console.log(`Link-MTU: ${config.mtu}`);

    config.mss = config.mtu - 40;

    if (config.sendEth) {
        config.ourMac = MACAddr.fromBytes(0x0A, randomByte(), randomByte(), randomByte(), randomByte(), randomByte());
        console.log(`Our MAC: ${config.ourMac}`);
        config.ethBcastHdr = new EthHdr();
        config.ethBcastHdr.ethtype = ETH_TYPE.IP;
        config.ethBcastHdr.saddr = config.ourMac;
        config.ethBcastHdr.daddr = MAC_BROADCAST;
    }

    config.ourIp = config.ourSubnet ? config.ourSubnet.ip : undefined;
    config.gatewayIp = config.serverIp;
    config.dnsServerIps = [config.gatewayIp!];
    configOut();

    if (needDHCP) {
        console.log("Starting DHCP procedure...");
        config.ipDoneCB = cb;
        dhcpNegotiate();
    } else if (cb) {
        setTimeout(cb, 0);
    }
}

function _workerMain(url: string, cb: VoidCB) {
    console.log(`Connecting to WSVPN: ${url}`);

    config.ws = new WebSocket(url);
    config.ws.binaryType = "arraybuffer";

    config.ws.onmessage = (msg) => {
        const data = msg.data;
        if (typeof data !== "string") {
            if (config.sendEth) {
                handleEthernet(data);
            } else {
                handleIP(data);
            }
            return;
        }

        handleInit(data, cb);
    };
}

onmessage = (e) => {
    const cmd = e.data[0];
    const msgId = e.data[1];
    switch (cmd) {
        case "connect":
            _workerMain(e.data[2], () => {
                postMessage(["connect",
                    msgId, config.ourIp, config.serverIp, config.gatewayIp, config.ourSubnet, config.mtu], "");
            });
            break;
        case "httpGet":
            httpGet(e.data[2], (err, res) => {
                postMessage(["httpGet", msgId, err, res], "");
            });
            break;
    }
};
