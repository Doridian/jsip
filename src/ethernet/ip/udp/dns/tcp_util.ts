import { IPAddr } from "../../address";
import { tcpConnect, TCPConnectHandler, TCPDisconnectHandler, TCPListener } from "../../tcp/stack";
import { dnsResolveOrIp } from "./index";

export function dnsTcpConnect(
    domainOrIp: string,
    port: number,
    func: TCPListener,
    cb: TCPConnectHandler,
    dccb: TCPDisconnectHandler,
) {
    dnsResolveOrIp(domainOrIp, (ip) => {
        if (!ip) {
            cb(false, undefined);
            return;
        }
        tcpConnect(ip as IPAddr, port, func, cb, dccb);
    });
}
