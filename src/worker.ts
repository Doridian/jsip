import { configOut } from "./config.js";
import { httpGet } from "./ethernet/ip/tcp/http/index.js";
import { addInterfaceEasy } from "./interface/util.js";
import { WSVPN } from "./wsvpn.js";

export function workerMain() {
    const location = document.location!;

    if (location.protocol === "file:" || location.hostname === "localhost") {
        return _workerMain("wss://doridian.net/ws").then(configOut);
    }

    const proto = (location.protocol === "http:") ? "ws:" : "wss:";
    return _workerMain(`${proto}//${location.host}/ws`).then(configOut);
}

function _workerMain(url: string) {
    const wsvpn = new WSVPN(url);
    addInterfaceEasy(wsvpn);
    return wsvpn.waitForInit();
}

onmessage = (e) => {
    const cmd = e.data[0];
    const msgId = e.data[1];
    switch (cmd) {
        case "connect":
            _workerMain(e.data[2]).then(() => {
                postMessage(["connect", msgId], "");
            });
            break;
        case "httpGet":
            httpGet(e.data[2]).then((res) => {
                postMessage(["httpGet", msgId, undefined, res], "");
            }).catch((err) => {
                postMessage(["httpGet", msgId, err, undefined], "");
            });
            break;
    }
};
