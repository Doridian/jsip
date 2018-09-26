import { stringIntoBuffer } from "../util";

export function makeDNSLabel(str: string) {
    const spl = str.split(".");
    const data = new Uint8Array(str.length + 2); // First len + 0x00 end
    let pos = 0;
    for (const s of spl) {
        if (s.length < 1) {
            continue;
        }
        data[pos] = s.length;
        stringIntoBuffer(s, data, pos + 1);
        pos += s.length + 1;
    }
    return data;
}
