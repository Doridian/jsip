import { expect } from "chai";
import { MACAddr } from "../ethernet/address.js";
import { ETH_TYPE } from "../ethernet/index.js";
import { IPAddr } from "../ethernet/ip/address.js";
import { IPPROTO } from "../ethernet/ip/index.js";
import { DNS_CLASS, DNS_TYPE } from "../ethernet/ip/udp/dns/index.js";
import { decodeHexString, parsePacketParts } from "./util.js";

// tslint:disable-next-line:max-line-length
const DNS_REQUEST = decodeHexString("b8aeed7c1e719c5c8ec0ee8a080045000039760a000080113f41c0a80214c0a80204e6280035002511a1b2ce01000001000000000000076578616d706c6503636f6d0000010001");
// tslint:disable-next-line:max-line-length
const DNS_REPLY = decodeHexString("9c5c8ec0ee8ab8aeed7c1e7108004500005ff2d640004011c24ec0a80204c0a802140035f06c004bb24ae60081800001000100000001076578616d706c6503636f6d0000010001076578616d706c6503636f6d00000100010000295e00045db8d82200002905ac000000000000");

const DNS_DOMAIN = "example.com";
const DNS_ADDR = IPAddr.fromString("93.184.216.34");
const MAC_SERVER = MACAddr.fromString("b8:ae:ed:7c:1e:71");
const MAC_CLIENT = MACAddr.fromString("9c:5c:8e:c0:ee:8a");
const IP_SERVER = IPAddr.fromString("192.168.2.4");
const IP_CLIENT = IPAddr.fromString("192.168.2.20");
const PORT_SERVER = 53;

const requestParts = parsePacketParts(DNS_REQUEST);

expect(requestParts.eth!.saddr).to.deep.equal(MAC_CLIENT);
expect(requestParts.eth!.daddr).to.deep.equal(MAC_SERVER);
expect(requestParts.eth!.ethtype).to.equal(ETH_TYPE.IP);

expect(requestParts.ip!.saddr).to.deep.equal(IP_CLIENT);
expect(requestParts.ip!.daddr).to.deep.equal(IP_SERVER);
expect(requestParts.ip!.protocol).to.equal(IPPROTO.UDP);

expect(requestParts.udp!.sport).to.equal(58920);
expect(requestParts.udp!.dport).to.equal(PORT_SERVER);

expect(requestParts.dns!.questions[0].name).to.equal(DNS_DOMAIN);
expect(requestParts.dns!.questions[0].class).to.equal(DNS_CLASS.IN);
expect(requestParts.dns!.questions[0].type).to.equal(DNS_TYPE.A);

requestParts.udp!.data = requestParts.dns!.toBytes();

const replyParts = parsePacketParts(DNS_REPLY);

expect(replyParts.eth!.saddr).to.deep.equal(MAC_SERVER);
expect(replyParts.eth!.daddr).to.deep.equal(MAC_CLIENT);
expect(replyParts.eth!.ethtype).to.equal(ETH_TYPE.IP);

expect(replyParts.ip!.saddr).to.deep.equal(IP_SERVER);
expect(replyParts.ip!.daddr).to.deep.equal(IP_CLIENT);
expect(replyParts.ip!.protocol).to.equal(IPPROTO.UDP);

expect(replyParts.udp!.sport).to.equal(PORT_SERVER);
expect(replyParts.udp!.dport).to.equal(61548);

expect(replyParts.dns!.questions[0].name).to.equal(DNS_DOMAIN);
expect(replyParts.dns!.questions[0].class).to.equal(DNS_CLASS.IN);
expect(replyParts.dns!.questions[0].type).to.equal(DNS_TYPE.A);

expect(replyParts.dns!.answers[0].name).to.equal(DNS_DOMAIN);
expect(replyParts.dns!.answers[0].class).to.equal(DNS_CLASS.IN);
expect(replyParts.dns!.answers[0].type).to.equal(DNS_TYPE.A);
expect(replyParts.dns!.answers[0].getData()).to.deep.equal(DNS_ADDR);
