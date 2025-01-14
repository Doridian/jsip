import { logError } from "./log.js";

type EventCB = (data: unknown) => void;
type IEventCBContainer = Record<string, EventCB[]>;

export class EventEmitter {
  private readonly events: IEventCBContainer = {};
  private readonly eventsOnce: IEventCBContainer = {};

  public on(event: string, cb: EventCB) {
    this.addInternal(this.events, event, cb);
  }

  public once(event: string, cb: EventCB) {
    this.addInternal(this.eventsOnce, event, cb);
  }

  protected emit(event: string, data: unknown) {
    this.emitInternal(data, this.events[event]);
    this.emitInternal(data, this.eventsOnce[event]);
    delete this.eventsOnce[event];
  }

  private addInternal(dest: IEventCBContainer, event: string, cb: EventCB) {
    const cbs = dest[event];
    if (!cbs) {
      dest[event] = [cb];
      return;
    }
    cbs.push(cb);
  }

  private emitInternal(data: unknown, targets?: EventCB[]) {
    if (!targets) {
      return;
    }
    for (const target of targets) {
      try {
        target(data);
      } catch (error) {
        logError(error as Error);
      }
    }
  }
}
