export class InvalidPortError extends Error {
    constructor() {
        super("Port out of valid range!");
    }
}

export function makeRandomPort() {
    return 4097 + Math.floor(Math.random() * 61347);
}

export function isValidPort(port: number) {
    return port > 0x00 && port <= 0xFF;
}

export function assertValidPort(port: number) {
    if (!isValidPort(port)) {
        throw new InvalidPortError();
    }
}
