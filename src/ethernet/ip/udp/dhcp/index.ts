import { MAC_NONE, MACAddr } from "../../../address.js";
import { ARP_HLEN, ARP_HTYPE } from "../../../arp/index.js";
import { IP_NONE, IPAddr } from "../../address.js";

const DHCP_MAGIC = new Uint8Array([0x63, 0x82, 0x53, 0x63]);
const DHCP_MAGIC_OFFSET = 236;

export const enum DHCP_OPTION {
    MODE = 53,
    SERVER = 54,
    IP = 50,
    OPTIONS = 55,
    SUBNET = 1,
    ROUTER = 3,
    DNS = 6,
    LEASETIME = 51,
    CLASSLESS_STATIC_ROUTE = 121,
}

export const enum DHCP_MODE {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    ACK = 5,
    NACK = 6,
}

export class DHCPPkt {
    public static fromPacket(packet: ArrayBuffer, offset: number) {
        const data = new Uint8Array(packet, offset);

        const dhcp = new DHCPPkt();
        dhcp.op = data[0];
        dhcp.htype = data[1];
        dhcp.hlen = data[2];
        dhcp.hops = data[3];
        dhcp.xid = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);
        dhcp.secs = data[9] + (data[8] << 8);
        dhcp.flags = data[11] + (data[10] << 8);
        dhcp.ciaddr = IPAddr.fromByteArray(data, 12);
        dhcp.yiaddr = IPAddr.fromByteArray(data, 16);
        dhcp.siaddr = IPAddr.fromByteArray(data, 20);
        dhcp.giaddr = IPAddr.fromByteArray(data, 24);
        dhcp.chaddr = MACAddr.fromByteArray(data, 28);

        if (data[DHCP_MAGIC_OFFSET] !== DHCP_MAGIC[0] ||
            data[DHCP_MAGIC_OFFSET + 1] !== DHCP_MAGIC[1] ||
            data[DHCP_MAGIC_OFFSET + 2] !== DHCP_MAGIC[2] ||
            data[DHCP_MAGIC_OFFSET + 3] !== DHCP_MAGIC[3]) {
            throw new Error("Invalid DHCP magic");
        }

        let i = DHCP_MAGIC_OFFSET + 4;
        let gotEnd = false;
        while (i < data.byteLength) {
            const optId = data[i];
            if (optId === 0xFF) {
                gotEnd = true;
                break;
            }

            const optLen = data[i + 1];
            dhcp.options.set(optId, new Uint8Array(packet, offset + i + 2, optLen));
            i += optLen + 2;
        }

        if (!gotEnd) {
            throw new Error("Invalid DHCP end");
        }

        return dhcp;
    }

    public op = 1;
    public htype = ARP_HTYPE;
    public hlen = ARP_HLEN;
    public hops = 0;
    public xid = 0;
    public secs = 0;
    public flags = 0;
    public ciaddr: IPAddr = IP_NONE;
    public yiaddr: IPAddr = IP_NONE;
    public siaddr: IPAddr = IP_NONE;
    public giaddr: IPAddr = IP_NONE;
    public chaddr = MAC_NONE;
    public options = new Map<DHCP_OPTION, Uint8Array>();

    public getFullLength() {
        let optLen = 1; // 0xFF always needed
        this.options.forEach((opt) => {
            optLen += 2 + opt.byteLength;
        });
        return DHCP_MAGIC_OFFSET + 4 + optLen;
    }

    public toPacket(array: ArrayBuffer, offset: number) {
        return this._toPacket(new Uint8Array(array, offset));
    }

    public toBytes() {
        const packet = new Uint8Array(this.getFullLength());
        this._toPacket(packet);
        return packet;
    }

    public _toPacket(packet: Uint8Array) {
        packet[0] = this.op;
        packet[1] = this.htype;
        packet[2] = this.hlen;
        packet[3] = this.hops;
        packet[4] = (this.xid >>> 24) & 0xFF;
        packet[5] = (this.xid >>> 16) & 0xFF;
        packet[6] = (this.xid >>> 8) & 0xFF;
        packet[7] = this.xid & 0xFF;
        packet[8] = (this.secs >>> 8) & 0xFF;
        packet[9] = this.secs & 0xFF;
        packet[10] = (this.flags >>> 8) & 0xFF;
        packet[11] = this.flags & 0xFF;
        this.ciaddr.toBytes(packet, 12);
        this.yiaddr.toBytes(packet, 16);
        this.siaddr.toBytes(packet, 20);
        this.giaddr.toBytes(packet, 24);
        this.chaddr.toBytes(packet, 28);
        packet[DHCP_MAGIC_OFFSET] = DHCP_MAGIC[0];
        packet[DHCP_MAGIC_OFFSET + 1] = DHCP_MAGIC[1];
        packet[DHCP_MAGIC_OFFSET + 2] = DHCP_MAGIC[2];
        packet[DHCP_MAGIC_OFFSET + 3] = DHCP_MAGIC[3];

        let optPos = DHCP_MAGIC_OFFSET + 4;
        this.options.forEach((opt, optId) => {
            const optLen = opt.byteLength;
            packet[optPos] = optId;
            packet[optPos + 1] = optLen;
            for (let i = 0; i < optLen; i++) {
                packet[optPos + 2 + i] = opt[i];
            }
            optPos += 2 + opt.byteLength;
        });
        packet[optPos] = 0xFF;

        return optPos;
    }
}
