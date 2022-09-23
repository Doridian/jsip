import { Buffer, BufferNotEnoughDataError } from "./buffer.js";

export abstract class CheckpointStream<T> extends Buffer {
    public parseOnAdd = true;
    private state: T;

    constructor(defaultState: T) {
        super();
        this.state = defaultState;
    }

    public getState() {
        return this.state;
    }

    public parse() {
        try {
            while (this.parseFunc(this.state)) {
                // Repeat
            }
        } catch (e) {
            if (e instanceof BufferNotEnoughDataError) {
                return;
            }
            throw e;
        }
    }

    protected abstract parseFunc(state?: T): boolean;  // Return true to run again

    protected setState(state: T) {
        this.state = state;
    }
}
