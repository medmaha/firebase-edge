// Runs the shared runtime smoke test inside a real workers isolate.
// The smoke script generates keys at module scope, which Workers forbid
// outside a request, so it is imported lazily from the fetch handler.
export default {
    async fetch() {
        try {
            await import('../runtime-smoke.mjs');
            return new Response('worker-ok');
        } catch (err) {
            return new Response(String(err?.stack ?? err), { status: 500 });
        }
    },
};
