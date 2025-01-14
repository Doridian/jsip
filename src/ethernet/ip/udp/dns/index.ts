import { boolToBit } from "../../../../util/index.js";
import { bufferToString } from "../../../../util/string.js";
import { IPAddr } from "../../address.js";
import { DNSAnswer } from "./answer.js";
import { DNSQuestion } from "./question.js";
import { IDNSParseState } from "./util.js";

const DNS_SEG_PTR = 0b11000000;
const DNS_SEG_MAX = 0b00111111;

export const enum DNS_TYPE {
    A = 0x0001,
    CNAME = 0x0005,
    // MX = 0x000F,
    NS = 0x0002,
}

export const enum DNS_CLASS {
    IN = 0x0001,
}

function parseDNSLabel(s: IDNSParseState) {
    const res = [];
    const donePointers = new Set<number>();
    let lastPos;
    let dataGood = false;

    while (s.pos < s.data.byteLength) {
        const segLen = s.data[s.pos++]!;
        if (segLen > DNS_SEG_MAX) {
            if ((segLen & DNS_SEG_PTR) !== DNS_SEG_PTR) {
                throw new Error(`Invalid DNS segment length ${segLen}`);
            }
            if (lastPos === undefined) {
                lastPos = s.pos + 1;
            }
            s.pos = ((segLen & DNS_SEG_MAX) << 8) | s.data[s.pos]!;
            if (donePointers.has(s.pos)) {
                throw new Error("Recursive pointers detected");
            }
            donePointers.add(s.pos);
            continue;
        }

        if (segLen === 0) {
            dataGood = true;
            break;
        }

        res.push(bufferToString(s.packet, s.pos + s.offset, segLen));
        s.pos += segLen;
    }

    if (lastPos !== undefined) {
        s.pos = lastPos;
    }

    if (!dataGood) {
        throw new Error("Unexpected DNS label end");
    }

    return res.join(".");
}

function parseAnswerSection(count: number, state: IDNSParseState) {
    const data = state.data;
    const answers = [];

    for (let i = 0; i < count; i++) {
        const a = new DNSAnswer();

        a.name = parseDNSLabel(state);
        a.type = data[state.pos + 1]! + (data[state.pos]! << 8);
        a.class = data[state.pos + 3]! + (data[state.pos + 2]! << 8);
        a.ttl = data[state.pos + 7]! +
            (data[state.pos + 6]! << 8) +
            (data[state.pos + 5]! << 16) +
            (data[state.pos + 4]! << 24);
        const rdlength = data[state.pos + 9]! + (data[state.pos + 8]! << 8);
        state.pos += 10;

        const dataRaw = new Uint8Array(state.packet, state.offset + state.pos, rdlength);
        if (a.class === DNS_CLASS.IN) {
            switch (a.type) {
                case DNS_TYPE.A:
                    a.setData(IPAddr.fromByteArray(dataRaw));
                    break;
                case DNS_TYPE.CNAME:
                case DNS_TYPE.NS:
                    a.setData(parseDNSLabel(state));
                    break;
            }
        }
        state.pos += rdlength;

        answers.push(a);
    }

    return answers;
}

export class DNSPkt {
    public static fromPacket(packet: ArrayBuffer, offset: number) {
        const data = new Uint8Array(packet, offset);

        const dns = new DNSPkt();
        dns.id = data[1]! + (data[0]! << 8);

        // [2]
        const flagData = data[2]!;
        dns.qr = (flagData & 0b10000000) !== 0;
        dns.opcode = (flagData >>> 3) & 0b1111;
        dns.aa = (flagData & 0b100) !== 0;
        dns.tc = (flagData & 0b10) !== 0;
        dns.rd = (flagData & 0b1) !== 0;

        // [3]
        const rData = data[3]!;
        dns.ra = (rData & 0b10000000) !== 0;
        dns.rcode = rData & 0b1111;

        const qdcount = data[5]! + (data[4]! << 8);
        const ancount = data[7]! + (data[6]! << 8);
        const nscount = data[9]! + (data[8]! << 8);
        const arcount = data[11]! + (data[10]! << 8);

        dns.questions = [];
        const state = { pos: 12, data, packet, offset };
        for (let i = 0; i < qdcount; i++) {
            const q = new DNSQuestion();
            q.name = parseDNSLabel(state);
            q.type = data[state.pos + 1]! + (data[state.pos]! << 8);
            q.class = data[state.pos + 3]! + (data[state.pos + 2]! << 8);
            state.pos += 4;
            dns.questions.push(q);
        }

        dns.answers = parseAnswerSection(ancount, state);
        dns.authority = parseAnswerSection(nscount, state);
        dns.additional = parseAnswerSection(arcount, state);

        return dns;
    }

    public id = 0;
    public qr = false;
    public opcode = 0;
    public aa = false;
    public tc = false;
    public rd = true;
    public ra = false;
    public rcode = 0;
    public questions: DNSQuestion[] = []; // QDCOUNT
    public answers: DNSAnswer[] = []; // ANCOUNT
    public authority: DNSAnswer[] = []; // NSCOUNT
    public additional: DNSAnswer[] = []; // ARCOUNT

    public getFullLength() {
        let len = 12;
        this.questions.forEach((q) => {
            len += (q.name.length + 2) + 4;
        });
        this.answers.forEach((a) => {
            len += (a.name.length + 2) + 10 + a.getDataLen();
        });
        this.authority.forEach((a) => {
            len += (a.name.length + 2) + 10 + a.getDataLen();
        });
        this.additional.forEach((a) => {
            len += (a.name.length + 2) + 10 + a.getDataLen();
        });
        return len;
    }

    public toPacket(array: ArrayBuffer, offset: number) {
        return this.toPacketInternal(new Uint8Array(array, offset));
    }

    public toBytes() {
        const packet = new Uint8Array(this.getFullLength());
        this.toPacketInternal(packet);
        return packet;
    }

    private toPacketInternal(packet: Uint8Array) {
        packet[0] = (this.id >>> 8) & 0xFF;
        packet[1] = this.id & 0xFF;
        packet[2] = boolToBit(this.qr, 7) |
                    (this.opcode << 3) |
                    boolToBit(this.aa, 2) |
                    boolToBit(this.tc, 1) |
                    boolToBit(this.rd, 0);
        packet[3] = boolToBit(this.ra, 7) | this.rcode;

        const qdcount = this.questions.length;
        const ancount = this.answers.length;
        const nscount = this.authority.length;
        const arcount = this.additional.length;

        packet[4] = (qdcount >>> 8) & 0xFF;
        packet[5] = qdcount & 0xFF;
        packet[6] = (ancount >>> 8) & 0xFF;
        packet[7] = ancount & 0xFF;
        packet[8] = (nscount >>> 8) & 0xFF;
        packet[9] = nscount & 0xFF;
        packet[10] = (arcount >>> 8) & 0xFF;
        packet[11] = arcount & 0xFF;

        let pos = 12;

        for (let i = 0; i < qdcount; i++) {
            pos = this.questions[i]!.write(packet, pos);
        }
        for (let i = 0; i < ancount; i++) {
            pos = this.answers[i]!.write(packet, pos);
        }
        for (let i = 0; i < nscount; i++) {
            pos = this.authority[i]!.write(packet, pos);
        }
        for (let i = 0; i < arcount; i++) {
            pos = this.additional[i]!.write(packet, pos);
        }

        return pos;
    }
}
