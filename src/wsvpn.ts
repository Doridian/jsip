import { IP_NONE, IPAddr } from "./ethernet/ip/address";
import { addRoute, flushRoutes } from "./ethernet/ip/router";
import { IPNet, IPNET_ALL } from "./ethernet/ip/subnet";
import { addDHCP } from "./ethernet/ip/udp/dhcp/stack";
import { addDNSServer, flushDNSServers } from "./ethernet/ip/udp/dns/index";
import { Interface } from "./interface/index";
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

        flushRoutes(this);
        flushDNSServers(this);

        switch (spl[2]) {
            case "TAP":
                this.ethernet = true;
            case "TUN":
                const subnet = IPNet.fromString(spl[3]);
                this.setIP(IPAddr.fromString(spl[3].split("/")[0]));
                addRoute(subnet, IP_NONE, this);
                addRoute(IPNET_ALL, subnet.getAddress(0), this);
                addDNSServer(subnet.getAddress(0), this);
                break;
            case "TAP_NOCONF":
                this.ethernet = true;
                needDHCP = true;
                break;
        }

        this.mtu = parseInt(spl[4], 10);

        logDebug(`${this.getName()} mode: ${spl[2]}`);

        if (needDHCP) {
            logDebug(`${this.getName()} starting DHCP procedure...`);
            addDHCP(this, cb).negotiate();
        } else if (cb) {
            setTimeout(cb, 0);
        }
    }
}
