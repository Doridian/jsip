import { IInterface } from "../../../interface/index.js";
import { logPacketError } from "../../../util/log.js";
import { assertValidPort, makeRandomPort } from "../../../util/port.js";
import { IPHdr, IPPROTO } from "../index.js";
import { sendIPPacket } from "../send.js";
import { registerIpHandler } from "../stack.js";
import { UDPPkt } from "./index.js";

export type UDPReplyFunc = (data: Uint8Array) => void;
export interface IUDPListener {
  gotPacket(
    pkt: UDPPkt,
    ip: IPHdr,
    iface: IInterface,
  ):
    | PromiseLike<Uint8Array>
    | PromiseLike<undefined>
    | PromiseLike<void>
    | Uint8Array
    | undefined
    | void;
}

const udpListeners = new Map<number, IUDPListener>();

class UDPEchoListener {
  public static gotPacket(pkt: UDPPkt, _: IPHdr, __: IInterface) {
    return pkt.data;
  }
}

class IPUDPListener {
  public static gotPacket(
    data: ArrayBuffer,
    offset: number,
    len: number,
    ipHdr: IPHdr,
    iface: IInterface,
  ) {
    const udpPkt = UDPPkt.fromPacket(data, offset, len, ipHdr);

    const listener = udpListeners.get(udpPkt.dport);
    if (listener && udpPkt.data) {
      try {
        Promise.resolve<Uint8Array | undefined | void>(
          listener.gotPacket(udpPkt, ipHdr, iface),
        )
          .then((reply?: Uint8Array | void) => {
            if (!reply) {
              return;
            }

            const ip = ipHdr.makeReply();
            const udp = new UDPPkt();
            udp.sport = udpPkt.dport;
            udp.dport = udpPkt.sport;
            udp.data = reply;
            sendIPPacket(ip, udp, iface);
          })
          .catch((error) => {
            logPacketError(error as Error, data);
          });
      } catch (error) {
        logPacketError(error as Error, data);
      }
    }
  }
}

export function udpListenRandom(func: IUDPListener) {
  let port = 0;
  do {
    port = makeRandomPort();
  } while (udpListeners.has(port));

  return udpListen(port, func);
}

export function udpListen(port: number, func: IUDPListener) {
  assertValidPort(port);

  if (udpListeners.has(port)) {
    return false;
  }

  enableUDP();
  udpListeners.set(port, func);
  return true;
}

export function udpCloseListener(port: number) {
  assertValidPort(port);

  return udpListeners.delete(port);
}

export function enableUDP() {
  registerIpHandler(IPPROTO.UDP, IPUDPListener);
}

export function enableUDPEcho() {
  udpListen(7, UDPEchoListener);
}
