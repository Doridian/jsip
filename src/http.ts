import { buffersToBuffer, bufferToString, stringToBuffer } from "./util";
import { dnsTcpConnect } from "./dns";

type HTTPHeaderMap = { [key: string]: string };

type HTTPResult = {
	statusCode: number;
	statusText: string;
	headers: HTTPHeaderMap;
	body: ArrayBuffer;
	url: string;
};

type HTTPCallback = (err: Error|undefined, res: HTTPResult|undefined) => void;

function _isHeaderEnd(ele: number, idx: number, arr: Uint8Array) {
	if (arr.byteLength < idx + 4) {
		return false;
	}
	return ele === 13 && arr[idx + 1] === 10 && arr[idx + 2] === 13 && arr[idx + 3] === 10;
}

function httpParse(datas: Uint8Array[]): HTTPResult {
	const data = buffersToBuffer(datas);
	const data8 = new Uint8Array(data);

	const headerEnd = data8.findIndex(_isHeaderEnd);

	let headersStr, body;
	if (headerEnd < 0) {
		headersStr = bufferToString(data, 0);
		body = new ArrayBuffer(0);
	} else {
		headersStr = bufferToString(new Uint8Array(data, 0, headerEnd), 0);
		body = new Uint8Array(data, headerEnd + 4);
	}

	const headers: HTTPHeaderMap = {};

	const headerSplit = headersStr.split('\r\n');
	const statusLine = headerSplit.shift();
	headerSplit.forEach((headerStr: string) => {
		const colonPos = headerStr.indexOf(':');
		if (colonPos < 0) {
			return;
		}
		headers[headerStr.substr(0, colonPos).trim().toLowerCase()] = headerStr.substr(colonPos + 1).trim();
	});

	let statusI = statusLine.indexOf(' ');
	if (statusI < 0) {
		throw new Error('Could not parse status line');
	}
	let statusI2 = statusLine.indexOf(' ', statusI + 1);
	if (statusI2 < 0) {
		throw new Error('Could not parse status line');
	}
	const statusCode = parseInt(statusLine.substring(statusI + 1, statusI2), 10);
	const statusText = statusLine.substring(statusI2 + 1);

	return {
		statusCode,
		statusText,
		headers,
		body,
		url: "",
	};
}

export function httpGet(urlStr: string, cb: HTTPCallback) {
	const url = new URL(urlStr);

	const datas: Uint8Array[] = [];
	dnsTcpConnect(url.hostname, url.port ? parseInt(url.port, 10) : 80, (data, _tcpConn) => {
		// Data
		datas.push(data);
	}, (res, conn) => {
		if (res === false) {
			try {
				cb(new Error('Could not connect'), undefined);
			} catch(e) {
				console.error(e.stack || e);
			}
			return;	
		}

		conn!.send(new Uint8Array(stringToBuffer(`GET ${url.pathname}${url.search} HTTP/1.1\r\nHost: ${url.host}\r\nUser-Agent: jsip\r\nConnection: close\r\n\r\n`)));
	}, () => {
		// Disconnect
		let res, err;
		try {
			res = httpParse(datas);
			res.url = url.href;
			err = undefined;
		} catch(e) {
			res = undefined;
			err = e;
		}

		try {
			cb(err, res);
		} catch(e) {
			console.error(e.stack || e);
		}
	});
}
