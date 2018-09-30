import { IP_NONE, IPAddr } from "./ethernet/ip/address.js";
import { addRoute, flushRoutes } from "./ethernet/ip/router.js";
import { IPNet, IPNET_ALL } from "./ethernet/ip/subnet.js";
import { addDHCP } from "./ethernet/ip/udp/dhcp/stack.js";
import { addDNSServer, flushDNSServers } from "./ethernet/ip/udp/dns/index.js";
import { Interface } from "./interface/index.js";
import { VoidCB } from "./util/index.js";
import { logDebug } from "./util/log.js";
import { handlePacket } from "./util/packet.js";

let maxNumber = 0;

export class WSVPN extends Interface {
    private ws: WebSocket;
    private ethernet: boolean = false;
    private mtu: number = 0;
    private donePromise: Promise<void>;
    private doneResolve?: VoidCB;

    public constructor(url: string) {
        super(`wsvpn${maxNumber++}`);

        this.donePromise = new Promise<void>((resolve, _) => {
            this.doneResolve = resolve;
        });

        logDebug(`Connecting to ${this.getName()}: ${url}`);

        this.ws = new WebSocket(url);
        this.ws.binaryType = "arraybuffer";

        this.ws.onmessage = (msg) => {
            const data = msg.data;
            if (typeof data !== "string") {
                handlePacket(data, this);
                return;
            }

            this.handleInit(data).then(this.doneResolve!);
        };
    }

    public waitForInit() {
        return this.donePromise;
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

    private handleInit(data: string) {
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
            return addDHCP(this).negotiate().then();
        } else {
            return Promise.resolve();
        }
    }
}
