export type VoidCB = () => void;

export function randomByte() {
  return Math.floor(Math.random() * 255);
}

export function boolToBit(bool: boolean, bit: number) {
  return bool ? 1 << bit : 0;
}
