import { IP_NONE } from "./ethernet/ip/address.js";
import { addRoute, flushRoutes } from "./ethernet/ip/router.js";
import { IPNet, IPNET_ALL } from "./ethernet/ip/subnet.js";
import { addDHCP } from "./ethernet/ip/udp/dhcp/stack.js";
import { addDNSServer, flushDNSServers } from "./ethernet/ip/udp/dns/stack.js";
import { Interface } from "./interface/index.js";
import { VoidCB } from "./util/index.js";
import { logDebug } from "./util/log.js";
import { handlePacket } from "./util/packet.js";

let maxNumber = 0;

interface ICommandCallback {
    resolve(data?: string): void;
    reject(err: Error): void;
}

export class WSVPN extends Interface {
    private ws: WebSocket;
    private ethernet: boolean = false;
    private mtu: number = 0;
    private donePromise: Promise<void>;
    private doneResolve?: VoidCB;
    private serverIp = IP_NONE;
    private nextCommandId = 0;
    private commandPromises: { [key: string]: ICommandCallback } = {};

    constructor(url: string) {
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
                handlePacket(data as ArrayBuffer, this);
                return;
            }

            this.handleText(data);
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

    public sendCommnd(command: string, args?: string[]): Promise<string | undefined> {
        const id = (this.nextCommandId++).toString();
        return new Promise((resolve, reject) => {
            this.commandPromises[id] = { resolve, reject };
            this.sendCommndFixedId(id, command, args);
        });
    }

    private sendCommndFixedId(id: string, command: string, args?: string[]) {
        let data = [id, command];
        if (args) {
            data = data.concat(args);
        }
        this.ws.send(data.join("|"));
    }

    private handleText(data: string) {
        const spl = data.split("|");
        if (spl.length < 2) {
            return;
        }

        const id = spl.shift()!;
        const command = spl.shift()!;
        let result = "OK";

        switch (command) {
            case "init":
                this.handleInit(spl).then(this.doneResolve!);
                break;
            case "addroute":
                if (this.serverIp === IP_NONE) {
                    result = "Don't support addroute with unmanaged ip config";
                } else {
                    addRoute(IPNet.fromString(spl[0]), this.serverIp, this);
                }
                break;
            case "reply":
                logDebug(`${this.getName()} Got reply ${spl.join(" ")} to ID ${id}`);
                const promise = this.commandPromises[id];
                if (promise) {
                    delete this.commandPromises[id];
                    promise.resolve(spl[0]);
                }
                return;
            default:
                result = "Unknown command";
                break;
        }

        this.sendCommndFixedId(id, "reply", [result]);
    }

    private handleInit(spl: string[]) {
        let needDHCP = false;

        flushRoutes(this);
        flushDNSServers(this);

        switch (spl[0]) {
            case "TAP":
                this.ethernet = true;
            case "TUN":
                const subnet = IPNet.fromString(spl[1]);
                this.setIP(subnet.getCreationIP());
                addRoute(subnet, IP_NONE, this);
                this.serverIp = subnet.getBaseIP();
                addRoute(IPNET_ALL, this.serverIp, this);
                addDNSServer(this.serverIp, this);
                break;
            case "TAP_NOCONF":
                this.ethernet = true;
                needDHCP = true;
                break;
        }

        this.mtu = parseInt(spl[2], 10);

        logDebug(`${this.getName()} mode: ${spl[0]}`);

        if (needDHCP) {
            logDebug(`${this.getName()} starting DHCP procedure...`);
            return addDHCP(this).negotiate();
        } else {
            return Promise.resolve();
        }
    }
}
