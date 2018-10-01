function processName(name: string) {
    return name.toLowerCase();
}

export class HTTPHeaders {
    private headerMap: { [key: string]: string[]; } = {};

    public add(name: string, value: string) {
        name = processName(name);
        const data = this.headerMap[name];
        if (data) {
            data.push(value);
        } else {
            this.headerMap[name] = [value];
        }
    }

    public set(name: string, value: string | string[]) {
        if (typeof value === "string") {
            value = [value];
        }
        this.headerMap[processName(name)] = value;
    }

    public has(name: string) {
        return !!this.get(name);
    }

    public delete(name: string) {
        delete this.headerMap[processName(name)];
    }

    public getAll() {
        return this.headerMap;
    }

    public get(name: string) {
        return this.headerMap[processName(name)];
    }

    public first(name: string) {
        const res = this.get(name);
        if (!res) {
            return undefined;
        }
        return res[0];
    }
}
