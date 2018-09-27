import { config } from "./config";
import { httpGet } from "./ethernet/ip/tcp/http/index";
import { VoidCB } from "./util/index";
import { connectWSVPN } from "./wsvpn";

export function workerMain(cb: VoidCB) {
    if (document.location.protocol === "file:") {
        _workerMain("wss://doridian.net/ws", cb);
        return;
    }

    const proto = (document.location.protocol === "http:") ? "ws:" : "wss:";
    _workerMain(`${proto}//${document.location.host}/ws`, cb);
}

function _workerMain(url: string, cb: VoidCB) {
    connectWSVPN(url, cb);
}

onmessage = (e) => {
    const cmd = e.data[0];
    const msgId = e.data[1];
    switch (cmd) {
        case "connect":
            _workerMain(e.data[2], () => {
                postMessage(["connect",
                    msgId, config.ourIp, config.mtu], "");
            });
            break;
        case "httpGet":
            httpGet(e.data[2], (err, res) => {
                postMessage(["httpGet", msgId, err, res], "");
            });
            break;
    }
};
