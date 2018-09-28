import { configOut } from "./config";
import { IP_NONE, IPAddr } from "./ethernet/ip/address";
import { addRoute, flushRoutes } from "./ethernet/ip/router";
import { IPNet, IPNET_ALL } from "./ethernet/ip/subnet";
import { dhcpNegotiate } from "./ethernet/ip/udp/dhcp/index";
import { addDNSServer, flushDNSServers } from "./ethernet/ip/udp/dns/index";
import { Interface } from "./interface";
import { VoidCB } from "./util/index";
import { logDebug } from "./util/log";
import { handlePacket } from "./util/packet";

let maxNumber = 0;

export class WSVPN extends Interface {
    private ws: WebSocket;
    private ethernet: boolean = false;
    private mtu: number = 0;

    public constructor(url: string, cb: VoidCB) {
        super(`wsvpn${maxNumber++}`);

        logDebug(`Connecting to ${this.getName()}: ${url}`);

        this.ws = new WebSocket(url);
        this.ws.binaryType = "arraybuffer";

        this.ws.onmessage = (msg) => {
            const data = msg.data;
            if (typeof data !== "string") {
                handlePacket(data, this);
                return;
            }

            this.handleInit(data, cb);
        };
    }

    public sendRaw(msg: ArrayBuffer) {
        this.ws.send(msg);
    }

    public getMTU() {
        return this.mtu;
    }

    public useEthernet() {
        return this.ethernet;
    }

    private handleInit(data: string, cb: VoidCB) {
        let needDHCP = false;
        // 1|init|TUN|192.168.3.1/24|1280
        const spl = data.split("|");

        flushRoutes();
        flushDNSServers();

        switch (spl[2]) {
            case "TAP":
                this.ethernet = true;
            case "TUN":
                const subnet = IPNet.fromString(spl[3]);
                this.setIP(IPAddr.fromString(spl[3].split("/")[0]));
                addRoute(subnet, IP_NONE, this);
                addRoute(IPNET_ALL, subnet.getAddress(0), this);
                addDNSServer(subnet.getAddress(0));
                break;
            case "TAP_NOCONF":
                this.ethernet = true;
                needDHCP = true;
                break;
        }

        this.mtu = parseInt(spl[4], 10);

        logDebug(`Mode: ${spl[2]}`);
        logDebug(`Link-MTU: ${this.mtu}`);
        logDebug(`Our MAC: ${this.getMAC()}`);

        configOut();

        if (needDHCP) {
            logDebug("Starting DHCP procedure...");
            dhcpNegotiate(this, cb);
        } else if (cb) {
            setTimeout(cb, 0);
        }
    }
}
