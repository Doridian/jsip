import { IInterface } from "../../interface/index.js";
import { IPacket } from "../../ipacket.js";
import { logError } from "../../util/log.js";
import { makeEthIPHdr } from "../arp/stack.js";
import { ETH_LEN, EthHdr } from "../index.js";
import { IPAddr } from "./address.js";
import { getRoute } from "./router.js";
import { IPHdr } from "./index.js";

export function sendPacketTo(dest: IPAddr, payload: IPacket) {
  const hdr = new IPHdr();
  hdr.daddr = dest;
  hdr.protocol = payload.getProto();
  sendIPPacket(hdr, payload, undefined);
}

export function sendIPPacket(
  ipHdr: IPHdr,
  payload: IPacket,
  iface?: IInterface,
) {
  let routeDestIp = ipHdr.daddr!;

  let route = getRoute(routeDestIp, iface);
  if (!route) {
    return;
  }

  let srcIp = route.src;
  if (route.router) {
    routeDestIp = route.router;
    if (!route.iface) {
      route = getRoute(routeDestIp, iface);
      if (!route) {
        return;
      }
      if (route.src) {
        srcIp = route.src;
      }
    }
  }

  if (route.iface) {
    iface = route.iface;
  } else if (!iface) {
    return;
  }

  if (srcIp) {
    ipHdr.saddr = srcIp;
  } else if (!ipHdr.saddr) {
    ipHdr.saddr = iface.getIP();
  }

  if (!iface.isEthernet()) {
    sendIPPacketInternal(ipHdr, payload, iface);
    return;
  }

  makeEthIPHdr(routeDestIp, iface)
    .then((ethHdr) => {
      sendIPPacketInternal(ipHdr, payload, iface, ethHdr);
    })
    .catch((error: Error) => {
      logError(error);
    });
}

function sendIPPacketInternal(
  ipHdr: IPHdr,
  payload: IPacket,
  iface: IInterface,
  ethIPHdr?: EthHdr,
) {
  const fullLength = payload.getFullLength();
  const cOffset = ipHdr.getContentOffset();
  const hdrLen = (ethIPHdr ? ETH_LEN : 0) + cOffset;
  const maxPacketSize = iface.getMTU() - cOffset;

  if (fullLength <= maxPacketSize) {
    ipHdr.setContentLength(fullLength);

    const reply = new ArrayBuffer(
      (ethIPHdr ? ETH_LEN : 0) + ipHdr.getFullLength(),
    );

    let offset = 0;
    if (ethIPHdr) {
      offset += ethIPHdr.toPacket(reply, offset);
    }
    offset += ipHdr.toPacket(reply, offset);
    offset += payload.toPacket(reply, offset, ipHdr);

    iface.sendPacket(reply);
    return;
  }

  if (ipHdr.df) {
    throw new Error(
      `Needing to send packet too big for MTU/MSS, but DF set (len=${fullLength} max=${maxPacketSize})`,
    );
  }

  const maxPacketSizeFrag = (maxPacketSize >>> 3) << 3;

  const pieceMax = Math.ceil(fullLength / maxPacketSizeFrag) - 1;
  ipHdr.mf = true;

  const replyPacket = new ArrayBuffer(fullLength);
  payload.toPacket(replyPacket, 0, ipHdr);
  const r8 = new Uint8Array(replyPacket);

  let pktData = new ArrayBuffer(hdrLen + maxPacketSizeFrag);
  let p8 = new Uint8Array(pktData);

  for (let i = 0; i <= pieceMax; i++) {
    const offset = maxPacketSizeFrag * i;
    let pieceLen = maxPacketSizeFrag;
    if (i === pieceMax) {
      ipHdr.mf = false;
      pieceLen = replyPacket.byteLength % maxPacketSizeFrag;
      pktData = new ArrayBuffer(hdrLen + pieceLen);
      p8 = new Uint8Array(pktData);
    }

    ipHdr.fragOffset = offset >>> 3;
    ipHdr.setContentLength(pieceLen);

    if (ethIPHdr) {
      ethIPHdr.toPacket(pktData, 0);
      ipHdr.toPacket(pktData, ETH_LEN);
    } else {
      ipHdr.toPacket(pktData, 0);
    }
    for (let j = 0; j < pieceLen; j++) {
      p8[j + hdrLen] = r8[j + offset]!;
    }

    iface.sendPacket(pktData);
  }
}
