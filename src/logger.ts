/**
 * Opt-in, level-based diagnostic logging for firebase-edge. OFF by default.
 */

export type LogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug' | 'trace';
export type ActiveLogLevel = Exclude<LogLevel, 'silent'>;

export interface LogEntry {
    level: ActiveLogLevel;
    /** Subsystem, e.g. `auth`, `firestore`, `storage`, `http`, `token`. Empty for the client itself. */
    scope: string;
    message: string;
    /** Epoch milliseconds. */
    time: number;
    /** Redacted, JSON-safe structured context. */
    data?: Record<string, unknown>;
    /**
     * The original error object (stack intact), when the entry is about a failure.
     * This is the very same object the caller receives, so it is NOT redacted; `data.error` is
     * the redacted, JSON-safe rendering. Prefer `data` when forwarding to third-party log drains.
     */
    error?: unknown;
}

/** Receives every entry at or above the configured level. Sink failures are swallowed. */
export type LogSink = (entry: LogEntry) => void | Promise<void>;

export interface LoggerOptions {
    /** Defaults to `'info'` when options are given without a level. */
    level?: LogLevel;
    /** Defaults to {@link consoleSink}. */
    sink?: LogSink;
}

/** Lazy data is only evaluated when the entry will actually be emitted. */
export type LogData = Record<string, unknown> | (() => Record<string, unknown>);

export interface Logger {
    readonly level: LogLevel;
    isEnabled(level: ActiveLogLevel): boolean;
    error(message: string, data?: LogData, error?: unknown): void;
    warn(message: string, data?: LogData, error?: unknown): void;
    info(message: string, data?: LogData, error?: unknown): void;
    debug(message: string, data?: LogData, error?: unknown): void;
    trace(message: string, data?: LogData, error?: unknown): void;
    child(scope: string): Logger;
}

const RANK: Record<LogLevel, number> = {
    silent: 0,
    error: 1,
    warn: 2,
    info: 3,
    debug: 4,
    trace: 5,
};

export const LOG_LEVELS = Object.keys(RANK) as LogLevel[];

export function isLogLevel(value: unknown): value is LogLevel {
    return typeof value === 'string' && Object.prototype.hasOwnProperty.call(RANK, value);
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const REDACTED = '[redacted]';
const MAX_STRING = 500;
const MAX_DEPTH = 6;
const MAX_KEYS = 50;
const MAX_ITEMS = 20;

/** Values under these keys are never emitted. */
const SECRET_KEY =
    /^(authorization|proxy-authorization|x-api-key|cookie|set-cookie|password|newpassword|privatekey|private_key|privatekeyid|private_key_id|token|idtoken|id_token|accesstoken|access_token|refreshtoken|refresh_token|assertion|apikey|api_key|key|oobcode|secret|signature|customattributes|downloadtoken|downloadtokens|firebasestoragedownloadtokens|x-goog-api-key)$/i;

/** Identifiers that are useful for tracing but should not be logged in full. */
const MASKED_KEY = /email|phone/i;

/** Secrets that can appear inside free-form strings (URLs, form bodies, error messages). */
const SECRET_PARAM =
    /(^|[?&;\s])(key|access_token|id_token|refresh_token|token|assertion|oobCode|X-Goog-Signature|X-Goog-Credential|X-Goog-Security-Token|signature)=[^&\s"'<>]*/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;
const PEM_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g;

export function scrubString(input: string): string {
    let out = input
        .replace(PEM_BLOCK, '[private-key]')
        .replace(BEARER, 'Bearer [redacted]')
        .replace(JWT, '[jwt]')
        .replace(SECRET_PARAM, (_m, lead: string, name: string) => `${lead}${name}=${REDACTED}`);
    if (out.length > MAX_STRING) out = `${out.slice(0, MAX_STRING)}...(+${out.length - MAX_STRING} chars)`;
    return out;
}

function maskEmail(value: string): string {
    const at = value.lastIndexOf('@');
    if (at < 1) return maskTail(value);
    return `${value[0]}***${value.slice(at)}`;
}

function maskTail(value: string): string {
    return value.length <= 4 ? '***' : `***${value.slice(-2)}`;
}

function maskValue(key: string, value: string): string {
    return /email/i.test(key) ? maskEmail(value) : maskTail(value);
}

export function serializeError(err: unknown, depth = 0): Record<string, unknown> | string {
    if (!(err instanceof Error)) return scrubString(String(err));
    const out: Record<string, unknown> = { name: err.name, message: scrubString(err.message) };
    const withExtras = err as Error & { code?: unknown; status?: unknown; cause?: unknown };
    if (withExtras.code !== undefined) {
        out.code = typeof withExtras.code === 'string' ? scrubString(withExtras.code) : withExtras.code;
    }
    if (withExtras.status !== undefined) out.status = withExtras.status;
    if (withExtras.cause !== undefined && depth < 3) out.cause = serializeError(withExtras.cause, depth + 1);
    return out;
}

/**
 * Deep-copies `value` into a JSON-safe, secret-free shape.
 * `maskedBy` is the key of an email/phone ancestor: every string beneath it is partially masked,
 * which also covers Firestore's wire format (`{ email: { stringValue: '...' } }`).
 */
export function redact(
    value: unknown,
    key = '',
    depth = 0,
    seen = new WeakSet<object>(),
    maskedBy?: string
): unknown {
    if (value === null || value === undefined) return value;
    if (key && SECRET_KEY.test(key)) return REDACTED;
    const mask = maskedBy ?? (key && MASKED_KEY.test(key) ? key : undefined);

    if (typeof value === 'string') return mask ? maskValue(mask, value) : scrubString(value);
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'bigint') return value.toString();
    if (typeof value === 'function') return '[Function]';
    if (typeof value === 'symbol') return value.toString();

    if (value instanceof Error) return serializeError(value);
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? 'Invalid Date' : value.toISOString();
    if (value instanceof Uint8Array) return `[Uint8Array ${value.byteLength} bytes]`;
    if (value instanceof ArrayBuffer) return `[ArrayBuffer ${value.byteLength} bytes]`;
    if (typeof Blob !== 'undefined' && value instanceof Blob) return `[Blob ${value.size} bytes]`;
    if (typeof ReadableStream !== 'undefined' && value instanceof ReadableStream) return '[ReadableStream]';

    if (typeof value !== 'object') return String(value);
    if (depth >= MAX_DEPTH) return '[MaxDepth]';
    if (seen.has(value)) return '[Circular]';
    seen.add(value);

    if (Array.isArray(value)) {
        const items = value.slice(0, MAX_ITEMS).map((v) => redact(v, key, depth + 1, seen, mask));
        if (value.length > MAX_ITEMS) items.push(`[+${value.length - MAX_ITEMS} more]`);
        return items;
    }

    const out: Record<string, unknown> = {};
    const entries = Object.entries(value as Record<string, unknown>);
    for (const [k, v] of entries.slice(0, MAX_KEYS)) out[k] = redact(v, k, depth + 1, seen, mask);
    if (entries.length > MAX_KEYS) out['[truncated]'] = `+${entries.length - MAX_KEYS} keys`;
    return out;
}

// ---------------------------------------------------------------------------
// Sinks and logger
// ---------------------------------------------------------------------------

/** Default sink: one console call per entry, prefixed with level and scope. */
export const consoleSink: LogSink = (entry) => {
    const tag = `[firebase-edge${entry.scope ? `:${entry.scope}` : ''}] ${entry.level.toUpperCase()}`;
    const args: unknown[] = [`${tag} ${entry.message}`];
    if (entry.data) args.push(entry.data);
    if (entry.error !== undefined) args.push(entry.error);
    switch (entry.level) {
        case 'error':
            console.error(...args);
            break;
        case 'warn':
            console.warn(...args);
            break;
        case 'info':
            console.info(...args);
            break;
        default:
            console.debug(...args);
    }
};

const noop = () => { };

/** Shared do-nothing logger used whenever logging is not enabled. */
export const noopLogger: Logger = {
    level: 'silent',
    isEnabled: () => false,
    error: noop,
    warn: noop,
    info: noop,
    debug: noop,
    trace: noop,
    child: () => noopLogger,
};

interface LoggerState {
    level: LogLevel;
    rank: number;
    sink: LogSink;
}

function build(state: LoggerState, scope: string): Logger {
    const emit = (level: ActiveLogLevel, message: string, data?: LogData, error?: unknown) => {
        if (RANK[level] > state.rank) return;
        try {
            const raw = typeof data === 'function' ? data() : data;
            let payload = raw ? (redact(raw) as Record<string, unknown>) : undefined;
            if (error !== undefined) payload = { ...payload, error: serializeError(error) };
            const entry: LogEntry = { level, scope, message, time: Date.now() };
            if (payload) entry.data = payload;
            if (error !== undefined) entry.error = error;
            const result = state.sink(entry);
            if (result && typeof (result as Promise<void>).then === 'function') {
                (result as Promise<void>).then(undefined, noop);
            }
        } catch {
            // A broken sink or data thunk must never affect the operation being logged.
        }
    };

    return {
        level: state.level,
        isEnabled: (level) => RANK[level] <= state.rank,
        error: (m, d, e) => emit('error', m, d, e),
        warn: (m, d, e) => emit('warn', m, d, e),
        info: (m, d, e) => emit('info', m, d, e),
        debug: (m, d, e) => emit('debug', m, d, e),
        trace: (m, d, e) => emit('trace', m, d, e),
        child: (sub) => build(state, scope ? `${scope}:${sub}` : sub),
    };
}

/**
 * Normalises the `logger` config option.
 * - `undefined` / `false` / `'silent'` -> disabled
 * - `true` -> `'info'` to the console
 * - a level string -> that level to the console
 * - `{ level?, sink? }` -> custom sink and/or level (level defaults to `'info'`)
 */
export function createLogger(option?: LogLevel | boolean | LoggerOptions): Logger {
    if (option === undefined || option === false) return noopLogger;

    const options: LoggerOptions =
        option === true ? { level: 'info' } : typeof option === 'string' ? { level: option } : option;
    const level = options.level ?? 'info';

    if (!isLogLevel(level)) {
        console.warn(
            `[firebase-edge] unknown log level ${JSON.stringify(level)}; logging disabled. ` +
            `Valid levels: ${LOG_LEVELS.join(', ')}`
        );
        return noopLogger;
    }
    if (level === 'silent') return noopLogger;

    return build({ level, rank: RANK[level], sink: options.sink ?? consoleSink }, '');
}
