import { CheckpointStream } from "../../../../util/stream.js";
import { arrayToString, buffersToBuffer, CHAR_CR, stringToBuffer } from "../../../../util/string.js";
import { IPAddr } from "../../address.js";
import { dnsResolveOrIp } from "../../udp/dns/stack.js";
import { TCPConn } from "../stack.js";
import { HTTPHeaders } from "./headers.js";

export interface IHTTPResult {
    statusCode: number;
    statusText: string;
    headers: HTTPHeaders;
    body: Uint8Array;
    url: URL;
}

export interface IHTTPOptions {
    url: URL;
    method?: string;
    body?: Uint8Array;
    headers?: HTTPHeaders;
    redirectLimit?: number;
    errorOnNon200?: boolean;
}

export interface IHTTPOptionsFilled {
    url: URL;
    method: string;
    body?: Uint8Array;
    headers: HTTPHeaders;
    redirectLimit: number;
    errorOnNon200: boolean;
}

const enum HttpParseState {
    StatusLine,
    HeaderLine,
    BodyFixedLength,
    BodyChunkLen,
    BodyChunkData,
    BodyChunkEnd,
    Done,
}

const enum HttpTransferEncoding {
    Identity = "identity",
    Chunked = "chunked",
}

class HttpCheckpointStream extends CheckpointStream<HttpParseState> {
    private statusCode: number = 0;
    private statusText: string = "";
    private headers: HTTPHeaders = new HTTPHeaders();
    private options: IHTTPOptionsFilled;
    private method: string;
    private nextReadLen: number = 0;
    private bodyChunks: Uint8Array[] = [];
    private resolve: (res: IHTTPResult) => void;

    constructor(options: IHTTPOptionsFilled, resolve: (res: IHTTPResult) => void) {
        super(HttpParseState.StatusLine);
        this.options = options;
        this.method = options.method;
        this.resolve = resolve;
    }

    public close() {
        this.setState(HttpParseState.Done);
    }

    protected parseFunc(state?: HttpParseState) {
        switch (state) {
            case HttpParseState.StatusLine:
                // Parse HTTP status line
                const statusLine = this.readTrimmedLine();
                if (statusLine.length < 1) {
                    throw new HttpInvalidErrror("Empty status line");
                }

                const statusI = statusLine.indexOf(" ");
                if (statusI < 0) {
                    throw new HttpInvalidErrror("No first space in status line");
                }
                const statusI2 = statusLine.indexOf(" ", statusI + 1);
                if (statusI2 < 0) {
                    throw new HttpInvalidErrror("No second space in status line");
                }
                this.statusCode = parseInt(statusLine.substring(statusI + 1, statusI2), 10);
                if (!isFinite(this.statusCode) || this.statusCode <= 0) {
                    throw new HttpInvalidErrror("Invalid response code in status line");
                }
                this.statusText = statusLine.substring(statusI2 + 1);

                this.setState(HttpParseState.HeaderLine);
            case HttpParseState.HeaderLine:
                // Parse (next) HTTP header
                const curHeader = this.readTrimmedLine();
                if (curHeader.length > 0) {
                    const colonPos = curHeader.indexOf(":");
                    if (colonPos < 0) {
                        throw new HttpInvalidErrror("Header without :");
                    }
                    const headerKey = curHeader.substr(0, colonPos).trim();
                    const headerValue = curHeader.substr(colonPos + 1).trim();
                    this.headers.add(headerKey, headerValue);
                    return true;
                }

                // Done with all headers here (empty line received), prepare for reading body
                if (this.method === "HEAD") {
                    return this.doneEmpty();
                }

                const transferEncoding = this.headers.first("Transfer-Encoding") || HttpTransferEncoding.Identity;

                switch (transferEncoding.toLowerCase()) {
                    case HttpTransferEncoding.Chunked:
                        this.setState(HttpParseState.BodyChunkLen);
                        break;

                    case HttpTransferEncoding.Identity:
                        const contentLengthStr = this.headers.first("Content-Length");
                        if (!contentLengthStr) {
                            return this.doneEmpty();
                        }

                        this.nextReadLen = parseInt(contentLengthStr, 10);
                        if (this.nextReadLen < 0 || !isFinite(this.nextReadLen)) {
                            throw new HttpInvalidErrror("Invalid Content-Length");
                        }

                        this.setState(HttpParseState.BodyFixedLength);
                        break;

                    default:
                        throw new HttpInvalidErrror(`Invalid Transfer-Encoding: ${transferEncoding}`);
                }

                return true;

            case HttpParseState.BodyFixedLength:
                // Parse body with explicit length
                return this.done(this.read(this.nextReadLen));

            case HttpParseState.BodyChunkLen:
                // Parse chunked body (chunk length)
                this.nextReadLen = parseInt(this.readTrimmedLine(), 16);
                if (!isFinite(this.nextReadLen) || this.nextReadLen < 0) {
                    throw new HttpInvalidErrror("Invalid chunk length");
                }

                this.setState(HttpParseState.BodyChunkData);
            case HttpParseState.BodyChunkData:
                // Parse chunked body (chunk data)
                this.bodyChunks.push(this.read(this.nextReadLen));

                this.setState(HttpParseState.BodyChunkEnd);
            case HttpParseState.BodyChunkEnd:
                // Parse chunked body (chunk terminating newline)
                const lineEnd = this.readLine();
                if (lineEnd.length > 2 || (lineEnd.length === 2 && lineEnd[0] !== CHAR_CR)) {
                    throw new HttpInvalidErrror("Garbage data at end of chunk!");
                }

                if (this.nextReadLen === 0) {
                    return this.done(new Uint8Array(buffersToBuffer(this.bodyChunks)));
                }

                this.setState(HttpParseState.BodyChunkLen);

                return true;

            case HttpParseState.Done:
                this.read(1);
                throw new HttpInvalidErrror("Garbage data!");
        }

        return true;
    }

    private readTrimmedLine() {
        return arrayToString(this.readLine()).trim();
    }

    private doneEmpty() {
        return this.done(new Uint8Array(0));
    }

    private done(body: Uint8Array) {
        this.close();

        this.resolve({
            body,
            headers: this.headers,
            statusCode: this.statusCode,
            statusText: this.statusText,
            url: this.options.url,
        });

        return false;
    }
}

function httpPromise(options: IHTTPOptionsFilled, resolve: (res: IHTTPResult) => void, reject: (err: Error) => void) {
    const body = options.body;
    const url = options.url;
    const headers = options.headers;
    headers.set("Connection", "close");
    headers.setIfNotExists("User-Agent", "jsip");
    headers.setIfNotExists("Host", url.host);

    if (url.username || url.password) {
        headers.setIfNotExists("Authorization", `Basic ${btoa(`${url.username}:${url.password}`)}`);
    }

    if (body) {
        headers.set("Content-Length", body.byteLength.toString());
    } else {
        headers.delete("Content-Length");
    }

    const stream = new HttpCheckpointStream(options, resolve);

    const tcpConn = new TCPConn();

    tcpConn.on("data", (data) => {
        try {
            stream.add(data as Uint8Array);
        } catch (e) {
            stream.close();
            reject(e as Error);
        }

        if (stream.getState() === HttpParseState.Done) {
            tcpConn.close();
        }
    });
    tcpConn.once("connect", () => {
        const data = [`${options.method} ${url.pathname}${url.search} HTTP/1.1`];
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

    dnsResolveOrIp(url.hostname)
    .then(ip => {
        tcpConn.connect(ip as IPAddr, url.port ? parseInt(url.port, 10) : 80);
    })
    .catch(reject);
}

// tslint:disable-next-line:max-classes-per-file
export class HttpError extends Error {
    public result: IHTTPResult;

    constructor(result: IHTTPResult) {
        super(`Invalid status code ${result.statusCode}`);
        this.result = result;
    }
}

// tslint:disable-next-line:max-classes-per-file
export class HttpInvalidErrror extends Error {
}

export function httpGet(options: IHTTPOptions): Promise<IHTTPResult> {
    const optionsFilled: IHTTPOptionsFilled = {
        errorOnNon200: false,
        headers: new HTTPHeaders(),
        method: "GET",
        redirectLimit: 3,
        ...options,
    };

    optionsFilled.headers = optionsFilled.headers.clone();
    optionsFilled.method = optionsFilled.method.toUpperCase();

    return httpGetInternal(optionsFilled)
    .then((result) => {
        if (!options.errorOnNon200) {
            return result;
        }

        if (result.statusCode < 200 || result.statusCode > 299) {
            throw new HttpError(result);
        }

        return result;
    });
}

function httpGetInternal(options: IHTTPOptionsFilled): Promise<IHTTPResult> {
    return new Promise<IHTTPResult>((resolve, reject) => {
        httpPromise(options, resolve, reject);
    })
    .then((result) => {
        if (options.redirectLimit === 0) {
            return result;
        }

        if (result.statusCode < 300 || result.statusCode > 399) {
            return result;
        }

        const location = result.headers.first("Location");
        if (!location) {
            return result;
        }

        const optionsClone = {...options};
        optionsClone.url = new URL(location, options.url);
        optionsClone.redirectLimit--;
        optionsClone.errorOnNon200 = false;
        return httpGetInternal(optionsClone);
    });
}
