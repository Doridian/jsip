import { IInterface } from "./index";

const interfaceTable = new Map<string, IInterface>();

export function getInterfaces() {
    return Array.from(interfaceTable.values());
}

export function addInterface(iface: IInterface) {
    interfaceTable.set(iface.getName(), iface);
}

export function deleteInterface(iface: IInterface) {
    interfaceTable.delete(iface.getName());
}
