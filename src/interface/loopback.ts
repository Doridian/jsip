import { IP_LOOPBACK, IPAddr } from "../ethernet/ip/address.js";
import { IPNET_LOOPBACK } from "../ethernet/ip/subnet.js";
import { handlePacket } from "../util/packet.js";
import { addInterface } from "./stack.js";
import { Interface } from "./index.js";

export class InterfaceLoopback extends Interface {
  public sendPacket(msg: ArrayBuffer): void {
    handlePacket(msg, this);
  }

  public isEthernet(): boolean {
    return false;
  }

  public getMTU(): number {
    return 65_535;
  }

  public isLocalDest(_: IPAddr): boolean {
    return true;
  }
}

let loopbackInterface: InterfaceLoopback | undefined;
export function getLoopbackInterface() {
  if (!loopbackInterface) {
    loopbackInterface = new InterfaceLoopback("lo");
    loopbackInterface.setIP(IP_LOOPBACK);
    loopbackInterface.setSubnet(IPNET_LOOPBACK);
  }
  return loopbackInterface;
}

export function addLoopback() {
  addInterface(getLoopbackInterface());
}
