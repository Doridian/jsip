import { IPAddr } from "../../address.js";
import { tcpConnect } from "../../tcp/stack.js";
import { dnsResolveOrIp } from "./index.js";

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
