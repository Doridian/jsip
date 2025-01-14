const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function arrayToBase64(array: Uint8Array) {
    let res = "";
    let maxLen = 0;

    for (let i = 0; i < array.length; i += 3) {
        const data = array[i + 2]! | (array[i + 1]! << 8) | (array[i]! << 16);
        maxLen = 3 - Math.min(array.length - i, 3);
        for (let j = 3; j >= maxLen; j--) {
            const b = (data >> (6 * j)) & 0b111111;
            res += chars[b];
        }
    }
    if (maxLen > 0) {
        res += "=".repeat(maxLen);
    }
    return res;
}
