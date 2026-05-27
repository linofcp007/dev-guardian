/**
 * MCP `notifications/progress` emitter.
 *
 * Tools instantiate one per long-running invocation. The emitter:
 *  - is a no-op when the host did not include a progressToken
 *  - posts on every `emit()` call (boundary events)
 *  - re-posts the last payload every 10 s as a heartbeat with an
 *    incrementing counter, so the host UI never looks frozen
 *
 * The emitter is decoupled from the SDK via the `ProgressNotifier`
 * interface so tests can verify exactly what would be sent without
 * spinning up an MCP transport.
 */
const NOOP = {
    emit: () => { },
    dispose: () => { },
};
export function makeProgressEmitter(options) {
    if (options.token === undefined || options.token === null)
        return NOOP;
    const setI = options.setIntervalImpl ?? setInterval;
    const clearI = options.clearIntervalImpl ?? clearInterval;
    const heartbeat = options.heartbeatMs ?? 10_000;
    const token = options.token;
    let lastPayload = null;
    let heartbeatCounter = 0;
    const interval = setI(() => {
        if (!lastPayload)
            return;
        heartbeatCounter += 1;
        options.notifier.send({
            ...lastPayload,
            // Heartbeat: re-send the last step but with a bumped progress value so
            // the host knows the server is alive even if no boundary happened.
            progress: typeof lastPayload.total === 'number'
                ? lastPayload.progress
                : lastPayload.progress + heartbeatCounter / 1000,
        });
    }, heartbeat);
    // Don't keep the event loop alive just for this timer.
    if (typeof interval.unref === 'function') {
        interval.unref();
    }
    return {
        emit: ({ step, total, message }) => {
            heartbeatCounter = 0; // reset; we just got a real event
            const payload = {
                progressToken: token,
                progress: total ? Math.min(100, (step / total) * 100) : step,
            };
            if (total !== undefined)
                payload.total = total;
            if (message !== undefined)
                payload.message = message;
            lastPayload = payload;
            options.notifier.send(payload);
        },
        dispose: () => {
            clearI(interval);
        },
    };
}
//# sourceMappingURL=progressEmitter.js.map