import { IPAddr } from "../../address";
import { tcpConnect } from "../../tcp/stack";
import { dnsResolveOrIp } from "./stack";

export function dnsTcpConnect(
    domainOrIp: string,
    port: number,
) {
    return dnsResolveOrIp(domainOrIp).then((ip) => {
        if (!ip) {
            throw new Error("Can't resolve domain");
        }
        return tcpConnect(ip as IPAddr, port);
    });
}
