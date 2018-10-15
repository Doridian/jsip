import { logError } from "./log.js";

type EventCB = (data: unknown) => void;
interface IEventCBContainer { [key: string]: EventCB[]; }

export class EventEmitter {
    private events: IEventCBContainer = {};
    private eventsOnce: IEventCBContainer = {};

    public on(event: string, cb: EventCB) {
        this._add(this.events, event, cb);
    }

    public once(event: string, cb: EventCB) {
        this._add(this.eventsOnce, event, cb);
    }

    protected emit(event: string, data: unknown) {
        this._emit(data, this.events[event]);
        this._emit(data, this.eventsOnce[event]);
        delete this.eventsOnce[event];
    }

    private _add(dest: IEventCBContainer, event: string, cb: EventCB) {
        const cbs = dest[event];
        if (!cbs) {
            dest[event] = [cb];
            return;
        }
        cbs.push(cb);
    }

    private _emit(data: unknown, targets?: EventCB[]) {
        if (!targets) {
            return;
        }
        targets.forEach((target) => {
            try {
                target(data);
            } catch (e) {
                logError(e as Error);
            }
        });
    }
}
