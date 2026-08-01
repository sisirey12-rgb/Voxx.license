const { EventEmitter } = require("events");

class NotificationEvents extends EventEmitter {
    constructor() {
        super();

        // Unlimited listeners
        this.setMaxListeners(0);
    }

    async emitAsync(event, payload = {}) {
        const listeners = this.listeners(event);

        if (!listeners.length)
            return;

        await Promise.allSettled(
            listeners.map(listener => listener(payload))
        );
    }
}

module.exports = new NotificationEvents();
