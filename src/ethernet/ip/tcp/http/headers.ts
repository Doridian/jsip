function processName(name: string) {
  return name.trim().toLowerCase();
}

export class HTTPHeaders {
  private headerMap: Record<string, string[]> = {};

  public clone() {
    const clone = new HTTPHeaders();
    for (const name in this.headerMap) {
      if (!this.headerMap.hasOwnProperty(name)) {
        continue;
      }
      clone.headerMap[name] = this.headerMap[name]!.slice(0);
    }
    return clone;
  }

  public add(name: string, value: string) {
    name = processName(name);
    const data = this.headerMap[name];
    if (data) {
      data.push(value);
    } else {
      this.headerMap[name] = [value];
    }
  }

  public setIfNotExists(name: string, value: string[] | string) {
    if (this.has(name)) {
      return;
    }
    this.set(name, value);
  }

  public set(name: string, value: string[] | string) {
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
