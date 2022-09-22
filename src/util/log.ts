export function logDebug(text: string) {
    // tslint:disable-next-line:no-console
    console.log(text);
}

export function logError(text: Error) {
    // tslint:disable-next-line:no-console
    console.error(text);
}

export function logPacketError(text: Error, packet: ArrayBuffer) {
    logError(text);
    // tslint:disable-next-line:no-console
    console.log(packet);
}
