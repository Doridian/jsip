import { IPHdr } from "../ethernet/ip/index";

export function computeChecksumIntermediate(bytes: Uint8Array, csum = 0) {
    for (let i = 0; i < bytes.length; i += 2) {
        csum += bytes[i] + ((bytes[i + 1] || 0) << 8);
    }
    return csum;
}

export function computeChecksumPseudo(ipHdr: IPHdr, proto: number, fullLen: number) {
    const pseudoIP8 = new Uint8Array(12);
    ipHdr.saddr.toBytes(pseudoIP8, 0);
    ipHdr.daddr.toBytes(pseudoIP8, 4);
    pseudoIP8[8] = 0;
    pseudoIP8[9] = proto;
    pseudoIP8[10] = (fullLen >>> 8) & 0xFF;
    pseudoIP8[11] = fullLen & 0xFF;
    return computeChecksumIntermediate(pseudoIP8);
}

export function computeChecksum(array: Uint8Array, csum = 0) {
    csum = computeChecksumIntermediate(array, csum);
    csum = (csum >>> 16) + (csum & 0xFFFF);
    return ~csum & 0xFFFF;
}
