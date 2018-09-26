import { buffersToBuffer, bufferToString, stringToBuffer } from "../../../../util/string";
import { dnsTcpConnect } from "../../udp/dns/tcp_util";

interface IHTTPHeaderMap { [key: string]: string; }

interface IHTTPResult {
    statusCode: number;
    statusText: string;
    headers: IHTTPHeaderMap;
    body: Uint8Array;
    url: string;
}

type HTTPCallback = (err?: Error, res?: IHTTPResult) => void;

function _isHeaderEnd(ele: number, idx: number, arr: Uint8Array) {
    if (arr.byteLength < idx + 4) {
        return false;
    }
    return ele === 13 && arr[idx + 1] === 10 && arr[idx + 2] === 13 && arr[idx + 3] === 10;
}

function httpParse(datas: Uint8Array[]): IHTTPResult {
    const data = buffersToBuffer(datas);
    const data8 = new Uint8Array(data);

    const headerEnd = data8.findIndex(_isHeaderEnd);

    let headersStr: string;
    let body: Uint8Array;
    if (headerEnd < 0) {
        headersStr = bufferToString(data, 0);
        body = new Uint8Array(0);
    } else {
        headersStr = bufferToString(data, 0, headerEnd);
        body = new Uint8Array(data, headerEnd + 4);
    }

    const headers: IHTTPHeaderMap = {};

    const headerSplit = headersStr.split("\r\n");
    const statusLine = headerSplit.shift();
    if (!statusLine) {
        throw new Error("Could not parse status line");
    }

    headerSplit.forEach((headerStr: string) => {
        const colonPos = headerStr.indexOf(":");
        if (colonPos < 0) {
            return;
        }
        headers[headerStr.substr(0, colonPos).trim().toLowerCase()] = headerStr.substr(colonPos + 1).trim();
    });

    const statusI = statusLine.indexOf(" ");
    if (statusI < 0) {
        throw new Error("Could not parse status line");
    }
    const statusI2 = statusLine.indexOf(" ", statusI + 1);
    if (statusI2 < 0) {
        throw new Error("Could not parse status line");
    }
    const statusCode = parseInt(statusLine.substring(statusI + 1, statusI2), 10);
    const statusText = statusLine.substring(statusI2 + 1);

    return {
        body,
        headers,
        statusCode,
        statusText,
        url: "",
    };
}

export function httpGet(urlStr: string, cb: HTTPCallback) {
    const url = new URL(urlStr);

    const datas: Uint8Array[] = [];
    dnsTcpConnect(url.hostname, url.port ? parseInt(url.port, 10) : 80, (data) => {
        // Data
        datas.push(data);
    }, (res, conn) => {
        // Connect
        if (res === false) {
            try {
                cb(new Error("Could not connect"), undefined);
            } catch (e) {
                console.error(e.stack || e);
            }
            return;
        }

        // tslint:disable-next-line:max-line-length
        const str = `GET ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nUser-Agent: jsip\r\nConnection: close\r\n\r\n`;
        conn!.send(new Uint8Array(stringToBuffer(str)));
    }, () => {
        // Disconnect
        let res: IHTTPResult | undefined;
        let err: Error | undefined;
        try {
            res = httpParse(datas);
            res.url = url.href;
            err = undefined;
        } catch (e) {
            res = undefined;
            err = e;
        }

        try {
            cb(err, res);
        } catch (e) {
            console.error(e.stack || e);
        }
    });
}
