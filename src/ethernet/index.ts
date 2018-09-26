import { MAC_NONE, MACAddr } from "./address";

export const enum ETH_TYPE {
    NONE = 0x0000,
    IP = 0x0800,
    IP6 = 0x86DD,
    ARP = 0x0806,
}

export const ETH_LEN = 14;

export class EthHdr {
    public static fromPacket(packet: ArrayBuffer, offset: number) {
        const eth = new EthHdr();
        const data = new Uint8Array(packet, offset);
        eth.daddr = MACAddr.fromByteArray(data, 0);
        eth.saddr = MACAddr.fromByteArray(data, 6);
        eth.ethtype = data[13] + (data[12] << 8);
        return eth;
    }

    public ethtype = ETH_TYPE.NONE;
    public saddr: MACAddr = MAC_NONE;
    public daddr: MACAddr = MAC_NONE;

    public makeReply() {
        const replyEth = new EthHdr();
        replyEth.ethtype = this.ethtype;
        replyEth.saddr = this.daddr;
        replyEth.daddr = this.saddr;
        return replyEth;
    }

    public getContentOffset() {
        return ETH_LEN;
    }

    public toPacket(array: ArrayBuffer, offset: number) {
        const packet = new Uint8Array(array, offset, ETH_LEN);
        this.daddr.toBytes(packet, 0);
        this.saddr.toBytes(packet, 6);
        packet[12] = (this.ethtype >>> 8) & 0xFF;
        packet[13] = this.ethtype & 0xFF;
        return ETH_LEN;
    }
}
