'use strict';

let worker;
let cmdId = 0;

const cmdCallbacks = {};

function sendCommand(cmd, args, cb) {
	const _id = cmdId++;
	cmdCallbacks[_id] = cb;
	worker.postMessage([cmd, _id].concat(args));
}

function httpGet(url, cb) {
	sendCommand('httpGet', [url], (data) => {
		cb(data[2], data[3]);
	});
}

function workerMain(cb) {
	worker = new Worker('worker.js');

	const proto = (document.location.protocol === 'http:') ? 'ws:' : 'wss:';
	sendCommand('connect', [`${proto}//${document.location.host}/ws`], cb);

	worker.onmessage = function (e) {
		const _id = e.data[1];
		const cb = cmdCallbacks[_id];
		if (cb) {
			cb(e.data);
			delete cmdCallbacks[_id];
		}
	};
}
