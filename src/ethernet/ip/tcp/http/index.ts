import { CheckpointStream } from "../../../../util/stream.js";
import { arrayToString, buffersToBuffer, stringToBuffer } from "../../../../util/string.js";
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

function httpParse(statusLine: string, headers: HTTPHeaders, body: Uint8Array): IHTTPResult {
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

const enum HttpParseState {
    StatusLine,
    HeaderLine,
    Body,
    BodyChunkLen,
    BodyChunkData,
    BodyChunkEnd,
    Done,
}

const enum HttpTransferEncoding {
    Identity = "identity",
    Chunked = "chunked",
}

class HttpInvalidException extends Error {
}

function _httpPromise(options: IHTTPOptions, resolve: (res: IHTTPResult) => void, reject: (err: Error) => void) {
    const body = options.body;
    const url = options.url;
    const method = (options.method || "GET").toUpperCase();

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

    // Response stuff here
    let nextChunkLen: number = 0;
    const bodyChunks: Uint8Array[] = [];

    let statusLine: string;
    const resHeaders = new HTTPHeaders();
    const stream = new CheckpointStream<HttpParseState>((thisStream, state) => {
        switch (state) {
            case HttpParseState.StatusLine:
                statusLine = arrayToString(thisStream.readLine()).trim();
                if (statusLine.length < 1) {
                    throw new HttpInvalidException("Empty status line");
                }
                thisStream.setState(HttpParseState.HeaderLine);
            case HttpParseState.HeaderLine:
                while (true) {
                    const curHeader = arrayToString(thisStream.readLine()).trim();
                    if (curHeader.length > 0) {
                        const colonPos = curHeader.indexOf(":");
                        if (colonPos < 0) {
                            throw new HttpInvalidException("Header without :");
                        }
                        const headerKey = curHeader.substr(0, colonPos).trim();
                        const headerValue = curHeader.substr(colonPos + 1).trim();
                        resHeaders.add(headerKey, headerValue);
                    } else {
                        if (method === "HEAD") {
                            thisStream.setState(HttpParseState.Done);
                            resolve(httpParse(statusLine, resHeaders, new Uint8Array(0)));
                            return false;
                        }

                        const transferEncoding = resHeaders.first("Transfer-Encoding") || HttpTransferEncoding.Identity;

                        switch (transferEncoding) {
                            case HttpTransferEncoding.Chunked:
                                thisStream.setState(HttpParseState.BodyChunkLen);
                                break;
                            case HttpTransferEncoding.Identity:
                                thisStream.setState(HttpParseState.Body);
                                break;
                            default:
                                throw new HttpInvalidException(`Invalid Transfer-Encoding: ${transferEncoding}`);
                        }

                        return true;
                    }
                }

            case HttpParseState.Body:
                const contentLength = parseInt(resHeaders.first("Content-Length")!, 10);
                if (contentLength < 0) {
                    throw new HttpInvalidException("Invalid Content-Length");
                }
                const content = thisStream.read(contentLength);
                thisStream.setState(HttpParseState.Done);
                resolve(httpParse(statusLine, resHeaders, content));
                return false;

            case HttpParseState.BodyChunkLen:
                nextChunkLen = parseInt(arrayToString(thisStream.readLine()).trim(), 16);
                if (nextChunkLen === 0) {
                    thisStream.setState(HttpParseState.Done);
                    resolve(httpParse(statusLine, resHeaders, new Uint8Array(buffersToBuffer(bodyChunks))));
                    return false;
                }
                thisStream.setState(HttpParseState.BodyChunkData);
            case HttpParseState.BodyChunkData:
                bodyChunks.push(thisStream.read(nextChunkLen));
                thisStream.setState(HttpParseState.BodyChunkEnd);
            case HttpParseState.BodyChunkEnd:
                thisStream.readLine();
                thisStream.setState(HttpParseState.BodyChunkLen);

                break;

            case HttpParseState.Done:
                return false;
        }

        return true;
    }, HttpParseState.StatusLine);

    dnsTcpConnect(url.hostname, url.port ? parseInt(url.port, 10) : 80)
    .then((tcpConn) => {
        tcpConn.on("data", (data) => {
            try {
                stream.add(data);
            } catch (e) {
                reject(e);
            }
        });
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
    })
    .catch(reject);
}

export function httpGet(options: IHTTPOptions) {
    return new Promise<IHTTPResult>((resolve, reject) => {
        _httpPromise(options, resolve, reject);
    });
}
