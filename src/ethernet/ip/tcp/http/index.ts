import { buffersToBuffer, bufferToString, stringToBuffer } from "../../../../util/string.js";
import { dnsTcpConnect } from "../../udp/dns/tcp_util.js";
import { HTTPHeaders } from "./headers.js";

export interface IHTTPResult {
    statusCode: number;
    statusText: string;
    headers: HTTPHeaders;
    body: Uint8Array;
    url?: URL;
}

export interface IHTTPOptions {
    url: URL;
    method?: string;
    body?: Uint8Array;
    headers?: HTTPHeaders;
}

function isHeaderEnd(ele: number, idx: number, arr: Uint8Array) {
    if (arr.byteLength < idx + 4) {
        return false;
    }
    return ele === 13 && arr[idx + 1] === 10 && arr[idx + 2] === 13 && arr[idx + 3] === 10;
}

function httpParse(datas: Uint8Array[]): IHTTPResult {
    const data = buffersToBuffer(datas);
    const data8 = new Uint8Array(data);

    const headerEnd = data8.findIndex(isHeaderEnd);

    let headersStr: string;
    let body: Uint8Array;
    if (headerEnd < 0) {
        headersStr = bufferToString(data, 0);
        body = new Uint8Array(0);
    } else {
        headersStr = bufferToString(data, 0, headerEnd);
        body = new Uint8Array(data, headerEnd + 4);
    }

    const headers = new HTTPHeaders();

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
        const headerKey = headerStr.substr(0, colonPos).trim();
        const headerValue = headerStr.substr(colonPos + 1).trim();
        headers.add(headerKey, headerValue);
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
    };
}

function _httpPromise(options: IHTTPOptions, resolve: (res: IHTTPResult) => void, reject: (err: Error) => void) {
    const body = options.body;
    const url = options.url;
    const method = options.method || "GET";

    const headers = options.headers || new HTTPHeaders();
    headers.set("connection", "close");
    headers.set("user-agent", "jsip");
    headers.set("host", url.host);
    if ((url.username || url.password) && !headers.has("authorization")) {
        headers.set("authorization", `Basic ${btoa(`${url.username}:${url.password}`)}`);
    }
    if (body) {
        headers.set("content-length", body.byteLength.toString());
    }

    const datas: Uint8Array[] = [];

    dnsTcpConnect(url.hostname, url.port ? parseInt(url.port, 10) : 80)
    .then((tcpConn) => {
        tcpConn.on("data", (data) => datas.push(data));
        tcpConn.once("connect", () => {
            const data = [`${method.toUpperCase()} ${url.pathname}${url.search} HTTP/1.1`];
            const headersMap = headers.getAll();
            for (const headerName of Object.keys(headersMap)) {
                for (const header of headersMap[headerName]) {
                    data.push(`${headerName}: ${header}`);
                }
            }
            tcpConn.send(new Uint8Array(stringToBuffer(data.join("\r\n") + "\r\n\r\n")));
            if (body) {
                tcpConn.send(body);
            }
        });
        tcpConn.once("close", () => {
            try {
                const res = httpParse(datas);
                res.url = url;
                resolve(res);
            } catch (e) {
                reject(e);
            }
        });
    })
    .catch(reject);
}

export function httpGet(options: IHTTPOptions) {
    return new Promise<IHTTPResult>((resolve, reject) => {
        _httpPromise(options, resolve, reject);
    });
}
