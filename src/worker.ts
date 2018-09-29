import { configOut } from "./config";
import { recomputeRoutes } from "./ethernet/ip/router";
import { httpGet } from "./ethernet/ip/tcp/http/index";
import { addLoopbackInterface } from "./interface/loopback";
import { addInterface } from "./interface/stack";
import { VoidCB } from "./util/index";
import { WSVPN } from "./wsvpn";

export function workerMain(cb: VoidCB) {
    const myCB = () => {
        configOut();
        cb();
    };

    const location = document.location!;

    if (location.protocol === "file:") {
        _workerMain("wss://doridian.net/ws", myCB);
        return;
    }

    const proto = (location.protocol === "http:") ? "ws:" : "wss:";
    _workerMain(`${proto}//${location.host}/ws`, myCB);
}

function _workerMain(url: string, cb: VoidCB) {
    const wsvpn = new WSVPN(url, cb);
    addLoopbackInterface();
    addInterface(wsvpn);
    recomputeRoutes();
}

onmessage = (e) => {
    const cmd = e.data[0];
    const msgId = e.data[1];
    switch (cmd) {
        case "connect":
            _workerMain(e.data[2], () => {
                postMessage(["connect", msgId], "");
            });
            break;
        case "httpGet":
            httpGet(e.data[2], (err, res) => {
                postMessage(["httpGet", msgId, err, res], "");
            });
            break;
    }
};
