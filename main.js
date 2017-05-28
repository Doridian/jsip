let worker;
function main() {
	worker = new Worker('worker.js');
	window.worker = worker;
}