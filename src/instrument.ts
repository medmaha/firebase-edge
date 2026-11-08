import { FirebaseError } from './errors';
import type { LogData, Logger } from './logger';

const MAX_CAPTURED_BODY = 64 * 1024;

const isThenable = (v: unknown): v is PromiseLike<unknown> =>
    !!v && typeof (v as PromiseLike<unknown>).then === 'function';

function describeUrl(input: RequestInfo | URL): string {
    if (typeof input === 'string') return input;
    if (input instanceof URL) return input.href;
    return input.url;
}

function headersToObject(init?: HeadersInit): Record<string, string> {
    const out: Record<string, string> = {};
    new Headers(init).forEach((value, key) => {
        out[key] = value;
    });
    return out;
}

function describeRequestBody(body: unknown): unknown {
    if (body === undefined || body === null) return undefined;
    if (typeof body === 'string') {
        try {
            return JSON.parse(body);
        } catch {
            return body;
        }
    }
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof Uint8Array) return `[binary ${body.byteLength} bytes]`;
    if (body instanceof ArrayBuffer) return `[binary ${body.byteLength} bytes]`;
    if (typeof Blob !== 'undefined' && body instanceof Blob) return `[binary ${body.size} bytes]`;
    return `[${Object.prototype.toString.call(body).slice(8, -1)}]`;
}

async function peekResponseBody(res: Response): Promise<unknown> {
    const type = res.headers.get('content-type') ?? '';
    if (!/json|text/i.test(type)) return `[${type || 'unknown content-type'}: body not captured]`;
    const length = Number(res.headers.get('content-length'));
    if (length > MAX_CAPTURED_BODY) return `[${length} bytes: body not captured]`;
    try {
        const text = await res.clone().text();
        try {
            return JSON.parse(text);
        } catch {
            return text;
        }
    } catch {
        return '[unreadable body]';
    }
}

/**
 * Wraps a fetch implementation so every outbound request is logged in one place
 * (Firestore, Storage, Identity Toolkit and the OAuth token endpoint all go through it).
 *
 * - debug: method, URL (secrets scrubbed), status, duration. 5xx/429 are logged as warnings.
 * - trace: also request headers/body and response body (redacted, size-capped).
 * - error: transport failures (DNS, TLS, abort, ...).
 *
 * Returns `fetchFn` untouched when logging is disabled.
 */
export function withFetchLogging(fetchFn: typeof fetch, log: Logger): typeof fetch {
    if (!log.isEnabled('error')) return fetchFn;
    const http = log.child('http');
    let seq = 0;

    return async (input, init) => {
        const id = ++seq;
        const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
        const url = describeUrl(input);
        const started = Date.now();

        http.debug('request', () => ({ id, method, url }));
        http.trace('request detail', () => ({
            id,
            headers: headersToObject(init?.headers),
            body: describeRequestBody(init?.body),
        }));

        let res: Response;
        try {
            res = await fetchFn(input, init);
        } catch (err) {
            http.error('request failed before a response was received', () => ({
                id,
                method,
                url,
                durationMs: Date.now() - started,
            }), err);
            throw err;
        }

        const summary = () => ({ id, method, url, status: res.status, durationMs: Date.now() - started });
        if (res.status >= 500 || res.status === 429) http.warn('response', summary);
        else http.debug('response', summary);

        if (http.isEnabled('trace')) {
            const body = await peekResponseBody(res);
            http.trace('response detail', () => ({ id, body }));
        }
        return res;
    };
}

/** Warn for caller-side failures (4xx, validation); error for anything that looks like a fault. */
function failureLevel(err: unknown): 'warn' | 'error' {
    if (err instanceof FirebaseError && !(err.status !== undefined && err.status >= 500)) return 'warn';
    return 'error';
}

type Describe = Record<string, (args: unknown[]) => Record<string, unknown>>;

/**
 * Wraps every function on an API object with start/ok/failed logging and timing.
 *
 * - debug: `<op> started`
 * - info:  `<op> ok` with duration
 * - warn:  `<op> failed` for client-side errors (4xx / validation)
 * - error: `<op> failed` for 5xx, network and unexpected errors
 * - trace: arguments and result (redacted)
 *
 * `describe` supplies the non-sensitive identifiers (collection, docId, uid, path)
 * shown at info level. `argNames` names each positional argument for trace output;
 * methods without a mapping log only their argument count. Arguments are never logged above trace.
 * Returns `api` untouched when logging is disabled.
 */
export function instrumentApi<T extends object>(
    scope: string,
    api: T,
    log: Logger,
    describe: Describe = {},
    argNames: Record<string, string[]> = {}
): T {
    if (!log.isEnabled('error')) return api;
    const l = log.child(scope);
    let seq = 0;
    const wrapped: Record<string, unknown> = {};

    for (const [name, member] of Object.entries(api)) {
        if (typeof member !== 'function') {
            wrapped[name] = member;
            continue;
        }

        wrapped[name] = (...args: unknown[]) => {
            const id = ++seq;
            const started = Date.now();
            const base = (): Record<string, unknown> => ({
                op: `${scope}.${name}`,
                id,
                ...safeDescribe(describe[name], args),
            });

            l.debug(`${name} started`, base);
            l.trace(`${name} args`, () => ({ ...base(), args: namedArgs(argNames[name], args) }));

            const ok = (result: unknown) => {
                l.info(`${name} ok`, () => ({ ...base(), durationMs: Date.now() - started }));
                l.trace(`${name} result`, () => ({ ...base(), result }));
                return result;
            };
            const failed = (err: unknown): never => {
                const data: LogData = () => ({ ...base(), durationMs: Date.now() - started });
                if (failureLevel(err) === 'error') l.error(`${name} failed`, data, err);
                else l.warn(`${name} failed`, data, err);
                throw err;
            };

            let out: unknown;
            try {
                out = (member as (...a: unknown[]) => unknown).apply(api, args);
            } catch (err) {
                return failed(err);
            }
            return isThenable(out) ? out.then(ok, failed) : ok(out);
        };
    }
    return wrapped as T;
}

/**
 * Positional arguments have no key for the redactor to key off (a bare string could be an ID token
 * or a password), so arguments are only ever logged under explicit names.
 */
function namedArgs(names: string[] | undefined, args: unknown[]): Record<string, unknown> {
    if (!names) return { argCount: args.length };
    const out: Record<string, unknown> = {};
    names.forEach((n, i) => {
        if (args[i] !== undefined) out[n] = args[i];
    });
    return out;
}

function safeDescribe(
    fn: ((args: unknown[]) => Record<string, unknown>) | undefined,
    args: unknown[]
): Record<string, unknown> {
    try {
        return fn ? fn(args) : {};
    } catch {
        return {};
    }
}
