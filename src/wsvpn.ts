import { IP_NONE } from "./ethernet/ip/address";
import { addRoute, flushRoutes } from "./ethernet/ip/router";
import { IPNet, IPNET_ALL } from "./ethernet/ip/subnet";
import { addDHCP } from "./ethernet/ip/udp/dhcp/stack";
import { addDNSServer, flushDNSServers } from "./ethernet/ip/udp/dns/stack";
import { Interface } from "./interface/index";
import { logDebug } from "./util/log";
import { handlePacket } from "./util/packet";
import { InitParameters, WSVPNBase } from "@wsvpn/web";

let maxNumber = 0;

export class WSVPNJSIP extends Interface {
    private init?: InitParameters = undefined;

    constructor(private adapter: WSVPNBase) {
        super(`wsvpn${maxNumber++}`);
        adapter.addEventListener("init", (ev) => {
            this.handleInit(ev.params);
        });
        adapter.addEventListener("packet", (ev) => {
            handlePacket(ev.packet.buffer.slice(ev.packet.byteOffset, ev.packet.byteLength), this);
        });
    }

    public waitForInit() {
        return this.adapter.connect();
    }

    public sendRaw(msg: ArrayBuffer) {
        return this.adapter.sendPacket(new Uint8Array(msg));
    }

    public getMTU() {
        return this.init!.mtu;
    }

    public useEthernet() {
        return this.init!.mode === "TAP";
    }

    private handleInit(params: InitParameters) {
        let needDHCP = false;

        flushRoutes(this);
        flushDNSServers(this);

        if (!params.do_ip_config) {
            needDHCP = true;
        } else {
            const subnet = IPNet.fromString(params.ip_address);
            this.setIP(subnet.getCreationIP());
            addRoute(subnet, IP_NONE, this);
            const serverIp = subnet.getBaseIP();
            addRoute(IPNET_ALL, serverIp, this);
            addDNSServer(serverIp, this);
        }

        if (needDHCP) {
            logDebug(`${this.getName()} starting DHCP procedure...`);
            return addDHCP(this).negotiate();
        } else {
            return Promise.resolve();
        }
    }
}
