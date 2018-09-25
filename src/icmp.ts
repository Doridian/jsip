import { computeChecksum } from "./util";

export class ICMPPkt {
    public static fromPacket(packet: ArrayBuffer, offset: number, len: number) {
        const icmp = new ICMPPkt();
        const data = new Uint8Array(packet, offset, len);
        icmp.type = data[0];
        icmp.code = data[1];
        icmp.checksum = data[3] + (data[2] << 8);
        icmp.rest = data[7] + (data[6] << 8) + (data[5] << 16) + (data[4] << 24);

        icmp.data = (len > 8) ? new Uint8Array(packet, offset + 8) : undefined;

        if (computeChecksum(data) !== 0) {
            throw new Error("Invalid ICMP checksum");
        }
        return icmp;
    }

    public type = 0;
    public code = 0;
    public rest = 0;
    public data?: Uint8Array;
    private checksum = 0;

    public toPacket(array: ArrayBuffer, offset: number) {
        const packet = new Uint8Array(array, offset, this.getFullLength());
        packet[0] = this.type;
        packet[1] = this.code;
        packet[2] = 0; // Checksum A
        packet[3] = 0; // Checksum B
        packet[4] = (this.rest >>> 24) & 0xFF;
        packet[5] = (this.rest >>> 16) & 0xFF;
        packet[6] = (this.rest >>> 8) & 0xFF;
        packet[7] = (this.rest) & 0xFF;
        if (this.data && this.data.byteLength > 0) {
            for (let i = 0; i < this.data.length; i++) {
                packet[8 + i] = this.data[i];
            }
        }
        this.checksum = computeChecksum(packet);
        packet[2] = this.checksum & 0xFF;
        packet[3] = (this.checksum >>> 8) & 0xFF;
        return packet.length;
    }

    public getFullLength() {
        if (!this.data) {
            return 8;
        }
        return this.data.byteLength + 8;
    }
}
