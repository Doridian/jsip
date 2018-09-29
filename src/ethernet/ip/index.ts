import { BitArray } from "../../util/bitfield.js";
import { computeChecksum } from "../../util/checksum.js";
import { logDebug } from "../../util/log.js";
import { IP_NONE, IPAddr } from "./address.js";

export const enum IPPROTO {
    NONE = 0,
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

export class IPHdr {
    public static fromPacket(packet: ArrayBuffer, offset: number) {
        const ipv4 = new IPHdr();
        const bit = new BitArray(packet, offset);
        ipv4.version = bit.read(4);
        if (ipv4.version !== 4) {
            logDebug(`Ignoring IP version: ${ipv4.version}`);
            return null;
        }
        ipv4.ihl = bit.read(4);
        ipv4.dscp = bit.read(6);
        ipv4.ecn = bit.read(2);
        ipv4.len = bit.read(16);
        ipv4.id = bit.read(16);
        const flags = bit.read(3);
        ipv4.df = (flags & 0x2) === 0x2;
        ipv4.mf = (flags & 0x1) === 0x1;
        ipv4.fragOffset = bit.read(13);
        ipv4.ttl = bit.read(8);
        ipv4.protocol = bit.read(8);
        ipv4.checksum = bit.read(16);
        ipv4.saddr = IPAddr.fromBytes(bit.read(8), bit.read(8), bit.read(8), bit.read(8));
        ipv4.daddr = IPAddr.fromBytes(bit.read(8), bit.read(8), bit.read(8), bit.read(8));
        const oLen = ipv4.ihl << 2;
        if (oLen > 20) {
            const oBeg = (bit.pos >>> 3) + offset;
            ipv4.options = packet.slice(oBeg, oBeg + (oLen - 20));
        } else {
            ipv4.options = new ArrayBuffer(0);
        }
        const checksum = computeChecksum(new Uint8Array(packet, offset, oLen));
        if (checksum !== 0) {
            logDebug(`Invalid IPv4 checksum: ${checksum} !== 0`);
            return null;
        }
        return ipv4;
    }

    public ihl = 5;
    public dscp = 0;
    public ecn = 0;
    public len = 0;
    public id = 0;
    public df = false;
    public mf = false;
    public fragOffset = 0;
    public protocol = IPPROTO.NONE;
    public saddr: IPAddr = IP_NONE;
    public daddr: IPAddr = IP_NONE;
    public options?: ArrayBuffer;
    private version = 4;
    private ttl = 64;
    private checksum = 0;

    public setContentLength(len: number) {
        this.len = this.getContentOffset() + len;
    }

    public getContentLength() {
        return this.len - this.getContentOffset();
    }

    public getFullLength() {
        return this.len;
    }

    public getContentOffset() {
        return this.ihl << 2;
    }

    public makeReply() {
        const replyIp = new IPHdr();
        replyIp.protocol = this.protocol;

        replyIp.saddr = this.daddr.isUnicast() ? this.daddr : IP_NONE;
        replyIp.daddr = this.saddr;

        return replyIp;
    }

    public toPacket(array: ArrayBuffer, offset: number) {
        const packet = new Uint8Array(array, offset, (this.options ? this.options.byteLength : 0) + 20);
        this.ihl = packet.length >>> 2;
        packet[0] = ((this.version & 0xF) << 4) + (this.ihl & 0xF);
        packet[1] = ((this.dscp & 0xFC) << 2) + (this.ecn & 0x3);
        packet[2] = (this.len >>> 8) & 0xFF;
        packet[3] = this.len & 0xFF;
        packet[4] = (this.id >>> 8) & 0xFF;
        packet[5] = this.id & 0xFF;
        const flags = (this.df ? 0x2 : 0x0) + (this.mf ? 0x1 : 0x0);
        packet[6] = (flags << 5) + ((this.fragOffset >>> 8) & 0x1F);
        packet[7] = this.fragOffset & 0xFF;
        packet[8] = this.ttl & 0xFF;
        packet[9] = this.protocol & 0xFF;
        packet[10] = 0; // Checksum A
        packet[11] = 0; // Checksum B
        this.saddr.toBytes(packet, 12);
        this.daddr.toBytes(packet, 16);
        if (this.options && this.options.byteLength > 0) {
            const o8 = new Uint8Array(this.options);
            for (let i = 0; i < o8.length; i++) {
                packet[i + 12] = o8[i];
            }
        }
        this.checksum = computeChecksum(packet);
        packet[10] = this.checksum & 0xFF;
        packet[11] = (this.checksum >>> 8) & 0xFF;
        return packet.length;
    }
}
