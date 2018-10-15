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

// tslint:disable-next-line:max-classes-per-file
class HttpCheckpointStream extends CheckpointStream<HttpParseState> {
    private statusLine: string = "";
    private resHeaders: HTTPHeaders = new HTTPHeaders();
    private method: string;
    private nextReadLen: number = 0;
    private bodyChunks: Uint8Array[] = [];
    private resolve: (res: IHTTPResult) => void;

    constructor(method: string, resolve: (res: IHTTPResult) => void) {
        super(HttpParseState.StatusLine);
        this.method = method;
        this.resolve = resolve;
    }

    public close() {
        this.setState(HttpParseState.Done);
    }

    protected parseFunc(state?: HttpParseState) {
        switch (state) {
            case HttpParseState.StatusLine:
                this.statusLine = arrayToString(this.readLine()).trim();
                if (this.statusLine.length < 1) {
                    throw new HttpInvalidException("Empty status line");
                }
                this.setState(HttpParseState.HeaderLine);
            case HttpParseState.HeaderLine:
                while (true) {
                    const curHeader = arrayToString(this.readLine()).trim();
                    if (curHeader.length > 0) {
                        const colonPos = curHeader.indexOf(":");
                        if (colonPos < 0) {
                            throw new HttpInvalidException("Header without :");
                        }
                        const headerKey = curHeader.substr(0, colonPos).trim();
                        const headerValue = curHeader.substr(colonPos + 1).trim();
                        this.resHeaders.add(headerKey, headerValue);
                    } else {
                        if (this.method === "HEAD") {
                            return this.done(new Uint8Array(0));
                        }

                        const transferEncoding = this.resHeaders.first("Transfer-Encoding") ||
                            HttpTransferEncoding.Identity;

                        switch (transferEncoding) {
                            case HttpTransferEncoding.Chunked:
                                this.setState(HttpParseState.BodyChunkLen);
                                break;
                            case HttpTransferEncoding.Identity:
                                const contentLengthStr = this.resHeaders.first("Content-Length");
                                if (!contentLengthStr) {
                                    return this.done(new Uint8Array(0));
                                }

                                this.nextReadLen = parseInt(contentLengthStr, 10);
                                if (this.nextReadLen < 0 || !isFinite(this.nextReadLen)) {
                                    throw new HttpInvalidException("Invalid Content-Length");
                                }

                                this.setState(HttpParseState.Body);
                                break;
                            default:
                                throw new HttpInvalidException(`Invalid Transfer-Encoding: ${transferEncoding}`);
                        }

                        return true;
                    }
                }

            case HttpParseState.Body:
                const content = this.read(this.nextReadLen);
                this.setState(HttpParseState.Done);
                return this.done(content);

            case HttpParseState.BodyChunkLen:
                this.nextReadLen = parseInt(arrayToString(this.readLine()).trim(), 16);
                if (!isFinite(this.nextReadLen) || this.nextReadLen < 0) {
                    throw new HttpInvalidException("Invalid chunk length");
                }

                if (this.nextReadLen === 0) {
                    this.setState(HttpParseState.BodyChunkEnd);
                    return true;
                } else {
                    this.setState(HttpParseState.BodyChunkData);
                }
            case HttpParseState.BodyChunkData:
                this.bodyChunks.push(this.read(this.nextReadLen));
                this.setState(HttpParseState.BodyChunkEnd);
            case HttpParseState.BodyChunkEnd:
                this.readLine();

                if (this.nextReadLen === 0) {
                    return this.done(new Uint8Array(buffersToBuffer(this.bodyChunks)));
                }

                this.setState(HttpParseState.BodyChunkLen);

                break;

            case HttpParseState.Done:
                this.read(1);
                throw new HttpInvalidException("Garbage data!");
        }

        return true;
    }

    private done(body: Uint8Array) {
        this.close();
        this.resolve(httpParse(this.statusLine, this.resHeaders, body));
        return false;
    }
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

    const stream = new HttpCheckpointStream(method, resolve);

    dnsTcpConnect(url.hostname, url.port ? parseInt(url.port, 10) : 80)
    .then((tcpConn) => {
        tcpConn.on("data", (data) => {
            try {
                stream.add(data);
            } catch (e) {
                stream.close();
                reject(e);
            }

            if (stream.getState() === HttpParseState.Done) {
                tcpConn.close();
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
