export function logDebug(text: string) {
  console.log(text);
}

export function logError(text: Error) {
  console.error(text);
}

export function logPacketError(text: Error, packet: ArrayBuffer) {
  logError(text);
  console.log(packet);
}
