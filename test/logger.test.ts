import { afterEach, describe, expect, it, vi } from 'vitest';
import {
    FirebaseError,
    configFromEnv,
    createFirebaseEdge,
    consoleSink,
    type LogEntry,
    type LogLevel,
} from '../src';
import { redact, scrubString, serializeError } from '../src/logger';
import {
    API_KEY,
    FS_DOCS,
    IDT_ADMIN,
    IDT_PUBLIC,
    PRIVATE_KEY_PEM,
    PROJECT_ID,
    DATABASE_NAME,
    TOKEN_URL,
    apiError,
    createMockFetch,
    routes,
    type Call,
    type Handler,
} from './helpers';

const baseConfig = (extra: Record<string, unknown> = {}) => ({
    projectId: PROJECT_ID,
    clientEmail: 'svc@test-project.iam.gserviceaccount.com',
    privateKeyId: 'kid-1',
    privateKey: PRIVATE_KEY_PEM,
    apiKey: API_KEY,
    databaseName: DATABASE_NAME,
    ...extra,
});

function setup(level: LogLevel | undefined, handler: Handler = () => undefined, extra = {}) {
    const entries: LogEntry[] = [];
    const mock = createMockFetch(handler);
    const fb = createFirebaseEdge(
        baseConfig({
            fetchFn: mock.fetchFn,
            ...(level ? { logger: { level, sink: (e: LogEntry) => void entries.push(e) } } : {}),
            ...extra,
        }) as any
    );
    return { fb, entries, ...mock };
}

const find = (entries: LogEntry[], scope: string, message: string) =>
    entries.find((e) => e.scope === scope && e.message === message);

afterEach(() => vi.restoreAllMocks());

// ---------------------------------------------------------------------------
describe('opt-in behaviour', () => {
    it('is silent by default: no sink, no console output', async () => {
        const spies = (['error', 'warn', 'info', 'debug', 'log'] as const).map((m) =>
            vi.spyOn(console, m).mockImplementation(() => {})
        );
        const { fb } = setup(undefined, routes([[`GET ${FS_DOCS}/users/u1`, () => ({ fields: {} })]]));
        await fb.firestore.get('users', 'u1');
        spies.forEach((s) => expect(s).not.toHaveBeenCalled());
    });

    it.each([false, 'silent'] as const)('logger: %s disables logging', async (logger) => {
        const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
        const { fb } = setup(undefined, routes([[`GET ${FS_DOCS}/users/u1`, () => ({ fields: {} })]]), {
            logger,
        });
        await fb.firestore.get('users', 'u1');
        expect(spy).not.toHaveBeenCalled();
    });

    it('logger: true logs at info to the console', async () => {
        const info = vi.spyOn(console, 'info').mockImplementation(() => {});
        const debug = vi.spyOn(console, 'debug').mockImplementation(() => {});
        const { fb } = setup(undefined, routes([[`GET ${FS_DOCS}/users/u1`, () => ({ fields: {} })]]), {
            logger: true,
        });
        await fb.firestore.get('users', 'u1');
        expect(info.mock.calls.some((c) => String(c[0]).includes('[firebase-edge:firestore] INFO get ok'))).toBe(true);
        expect(debug).not.toHaveBeenCalled();
    });

    it('options without a level default to info', async () => {
        const entries: LogEntry[] = [];
        const { fb } = setup(undefined, routes([[`GET ${FS_DOCS}/users/u1`, () => ({ fields: {} })]]), {
            logger: { sink: (e: LogEntry) => void entries.push(e) },
        });
        await fb.firestore.get('users', 'u1');
        expect(new Set(entries.map((e) => e.level))).toEqual(new Set(['info']));
    });

    it('keeps the public surface of the client unchanged', () => {
        const { fb } = setup('trace');
        expect(Object.keys(fb).sort()).toEqual(['auth', 'firestore', 'getAccessToken', 'storage']);
        expect(Object.keys(fb.storage)).toContain('bucket');
    });

    it('warns once about an unknown level and stays silent', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const entries: LogEntry[] = [];
        createFirebaseEdge(
            baseConfig({
                fetchFn: createMockFetch().fetchFn,
                logger: { level: 'loud', sink: (e: LogEntry) => void entries.push(e) },
            }) as any
        );
        expect(warn).toHaveBeenCalledTimes(1);
        expect(String(warn.mock.calls[0][0])).toMatch(/unknown log level "loud".*Valid levels/);
        expect(entries).toEqual([]);
    });
});

// ---------------------------------------------------------------------------
describe('levels', () => {
    const handler = routes([
        [`POST ${IDT_ADMIN}/accounts`, () => ({ localId: 'u1' })],
        [`PATCH ${FS_DOCS}/users/u1`, () => ({})],
    ]);
    const run = async (level: LogLevel) => {
        const h = setup(level, handler);
        await h.fb.auth.createUser({ email: 'jane@example.com', password: 'hunter2-secret' });
        return h.entries;
    };

    it('error: a successful operation produces nothing', async () => {
        expect(await run('error')).toEqual([]);
    });

    it('info: operation results and lifecycle only', async () => {
        const entries = await run('info');
        expect(new Set(entries.map((e) => e.level))).toEqual(new Set(['info']));
        const ok = find(entries, 'auth', 'createUser ok')!;
        expect(ok.data).toMatchObject({ op: 'auth.createUser' });
        expect(typeof ok.data!.durationMs).toBe('number');
        expect(find(entries, 'firestore', 'set ok')?.data).toMatchObject({
            collection: 'users',
            docId: 'u1',
        });
        expect(find(entries, '', 'client created')?.data).toMatchObject({
            projectId: PROJECT_ID,
            logLevel: 'info',
        });
    });

    it('debug: adds http summaries and token activity', async () => {
        const entries = await run('debug');
        const levels = new Set(entries.map((e) => e.level));
        expect(levels.has('debug')).toBe(true);
        expect(levels.has('trace')).toBe(false);
        const res = entries.filter((e) => e.scope === 'http:' + '' || e.scope === 'http').filter((e) => e.message === 'response');
        expect(res.length).toBeGreaterThan(0);
        expect(res[0].data).toMatchObject({ status: 200, method: expect.any(String) });
        expect(find(entries, 'token', 'token cache miss')).toBeTruthy();
        expect(find(entries, 'token', 'access token refreshed')).toBeTruthy();
        expect(find(entries, '', 'service account normalised')?.data).toMatchObject({
            privateKeyLooksLikePem: true,
        });
    });

    it('trace: adds arguments, results and payloads', async () => {
        const entries = await run('trace');
        expect(find(entries, 'auth', 'createUser args')).toBeTruthy();
        expect(find(entries, 'http', 'request detail')).toBeTruthy();
        expect(find(entries, 'http', 'response detail')).toBeTruthy();
    });

    it('tags nested calls so a trace shows what createUser triggered', async () => {
        const entries = await run('info');
        const order = entries.map((e) => `${e.scope}:${e.message}`);
        expect(order.indexOf('firestore:set ok')).toBeLessThan(order.indexOf('auth:createUser ok'));
    });
});

// ---------------------------------------------------------------------------
describe('redaction', () => {
    it('never emits credentials or raw PII at any level', async () => {
        const handler: Handler = (call) => {
            // realistic Google-style failures (our mock would otherwise echo URLs into errors)
            if (call.url.startsWith(`${IDT_PUBLIC}/accounts:resetPassword`)) return apiError('INVALID_OOB_CODE', 400);
            if (call.url.startsWith(`${IDT_ADMIN}/accounts:update`)) return {};
            if (call.url.startsWith(`${FS_DOCS}:commit`)) return {};
            if (call.url === `${IDT_ADMIN}/accounts`) return { localId: 'u1' };
            if (call.url.startsWith(`${FS_DOCS}/users/u1`)) return {};
            if (call.url.startsWith(`${IDT_PUBLIC}/accounts:lookup`))
                return { users: [{ localId: 'u1', email: 'jane@example.com' }] };
            if (call.url.startsWith(`${IDT_ADMIN}/accounts:lookup`))
                return { users: [{ localId: 'u1', email: 'jane@example.com' }] };
            return undefined;
        };
        const { fb, entries, calls } = setup('trace', handler);

        await fb.auth.createUser({ email: 'jane@example.com', password: 'hunter2-secret' });
        await fb.auth.verifyIdToken('id-token-secret');
        await fb.auth.resetUserPassword('u1', 'brand-new-pw-123').catch(() => {});
        await fb.auth.confirmPasswordReset('oob-code-secret', 'another-pw-456').catch(() => {});
        const url = await fb.storage.signedUrl('a.txt', { expiresIn: 60 });

        const assertion = new URLSearchParams(
            String(calls.find((c: Call) => c.url === TOKEN_URL)!.body)
        ).get('assertion')!;
        const signature = new URL(url).searchParams.get('X-Goog-Signature')!;
        const pemBody = PRIVATE_KEY_PEM.split('\n')[1];

        const dump = JSON.stringify(entries);
        for (const secret of [
            'hunter2-secret',
            'id-token-secret',
            'brand-new-pw-123',
            'another-pw-456',
            'oob-code-secret',
            'test-token-1',
            API_KEY,
            assertion,
            signature,
            pemBody,
            'jane@example.com',
        ]) {
            expect(secret.length).toBeGreaterThan(5);
            expect(dump, `leaked: ${secret.slice(0, 20)}`).not.toContain(secret);
        }
        expect(dump).toContain('j***@example.com');
        expect(dump).toContain('[redacted]');
    });

    it('traces name arguments and never prints a bare positional secret', async () => {
        const { fb, entries } = setup('trace', routes([[`POST ${IDT_PUBLIC}/accounts:lookup`, () => ({ users: [{ localId: 'u1' }] })]]));
        await fb.auth.verifyIdToken('id-token-secret');
        const args = find(entries, 'auth', 'verifyIdToken args')!;
        expect(args.data!.args).toEqual({ idToken: '[redacted]' });
    });

    it('masks emails nested in Firestore typed values', () => {
        const out: any = redact({ fields: { email: { stringValue: 'jane@example.com' }, name: { stringValue: 'Jane' } } });
        expect(out.fields.email.stringValue).toBe('j***@example.com');
        expect(out.fields.name.stringValue).toBe('Jane');
    });

    it('redact() handles nesting, masking, binary, truncation and cycles', () => {
        const cyclic: any = { name: 'x' };
        cyclic.self = cyclic;
        const out: any = redact({
            password: 'p',
            nested: { Authorization: 'Bearer abc.def', idToken: 't', keep: 1 },
            email: 'a@b.com',
            emails: ['one@x.com', 'two@y.com'],
            phoneNumber: '+2207001234',
            bytes: new Uint8Array(10),
            long: 'x'.repeat(2000),
            cyclic,
            fn: () => 1,
        });
        expect(out.password).toBe('[redacted]');
        expect(out.nested).toEqual({ Authorization: '[redacted]', idToken: '[redacted]', keep: 1 });
        expect(out.email).toBe('a***@b.com');
        expect(out.emails).toEqual(['o***@x.com', 't***@y.com']);
        expect(out.phoneNumber).toBe('***34');
        expect(out.bytes).toBe('[Uint8Array 10 bytes]');
        expect(out.long.length).toBeLessThan(600);
        expect(out.cyclic.self).toBe('[Circular]');
        expect(out.fn).toBe('[Function]');
    });

    it('scrubs error codes too (they can carry server-controlled text)', () => {
        const err = Object.assign(new Error('x'), { code: 'BAD https://h.test/p?key=AIzaSecret' });
        expect(JSON.stringify(serializeError(err))).not.toContain('AIzaSecret');
    });

    it('scrubString() removes secrets embedded in URLs, bodies and messages', () => {
        const s = scrubString(
            'GET https://x.test/v1?key=AIzaSecret&alt=media&X-Goog-Signature=abcdef ' +
                'Bearer ya29.token body assertion=eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.sig-nature ' +
                '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----'
        );
        expect(s).not.toMatch(/AIzaSecret|abcdef|ya29|eyJhbGci|MIIE/);
        expect(s).toContain('alt=media');
        expect(s).toContain('key=[redacted]');
    });
});

// ---------------------------------------------------------------------------
describe('failures are captured with the right severity', () => {
    it('4xx is a warning and carries the Google error code', async () => {
        const { fb, entries } = setup(
            'info',
            routes([[`GET ${FS_DOCS}/users/u1`, () => apiError('denied', 403, { status: 'PERMISSION_DENIED' })]])
        );
        await expect(fb.firestore.get('users', 'u1')).rejects.toMatchObject({ status: 403 });
        const e = find(entries, 'firestore', 'get failed')!;
        expect(e.level).toBe('warn');
        expect(e.data).toMatchObject({ collection: 'users', docId: 'u1' });
        expect((e.data!.error as any).code).toBe('PERMISSION_DENIED');
        expect(e.error).toBeInstanceOf(FirebaseError);
    });

    it('5xx is an error', async () => {
        const { fb, entries } = setup(
            'warn',
            routes([[`GET ${FS_DOCS}/users/u1`, () => apiError('boom', 503)]])
        );
        await expect(fb.firestore.get('users', 'u1')).rejects.toBeInstanceOf(FirebaseError);
        expect(find(entries, 'firestore', 'get failed')?.level).toBe('error');
        expect(find(entries, 'http', 'response')?.level).toBe('warn');
    });

    it('a transport failure is logged at the http layer and the operation', async () => {
        const { fb, entries } = setup('error', (call) => {
            if (call.url === TOKEN_URL) return undefined;
            throw new TypeError('fetch failed');
        });
        await expect(fb.firestore.get('users', 'u1')).rejects.toThrow('fetch failed');
        expect(find(entries, 'http', 'request failed before a response was received')?.level).toBe('error');
        expect(find(entries, 'firestore', 'get failed')?.level).toBe('error');
    });

    it('a 404 that the library handles is not a failure', async () => {
        const { fb, entries } = setup(
            'debug',
            routes([[`GET ${FS_DOCS}/users/missing`, () => apiError('nope', 404)]])
        );
        await expect(fb.firestore.get('users', 'missing')).resolves.toBeNull();
        expect(entries.some((e) => e.level === 'warn' || e.level === 'error')).toBe(false);
    });

    it('logs a malformed private key (previously an opaque DOMException)', async () => {
        const { fb, entries } = setup('error', undefined, { privateKey: 'definitely not a pem!' });
        await expect(fb.getAccessToken('s')).rejects.toBeTruthy();
        expect(find(entries, 'token:signer', 'x')).toBeUndefined();
        const e = entries.find((x) => x.message.startsWith('failed to import the service-account private key'));
        expect(e?.level).toBe('error');
        expect(entries.some((x) => x.message === 'access token request failed')).toBe(true);
    });
});

// ---------------------------------------------------------------------------
describe('previously swallowed errors', () => {
    it('verifyIdToken keeps the cause and flags non-auth failures', async () => {
        const down = setup('debug', routes([[`POST ${IDT_PUBLIC}/accounts:lookup`, () => apiError('down', 503)]]));
        const err: any = await down.fb.auth.verifyIdToken('t').catch((e) => e);
        expect(err).toMatchObject({ code: 'INVALID_ID_TOKEN', status: 401 });
        expect(err.cause).toBeInstanceOf(FirebaseError);
        expect(err.cause.status).toBe(503);
        expect(
            down.entries.find((e) => e.message.includes('non-auth reason'))?.level
        ).toBe('warn');

        const bad = setup('debug', routes([[`POST ${IDT_PUBLIC}/accounts:lookup`, () => apiError('INVALID_ID_TOKEN', 400)]]));
        await expect(bad.fb.auth.verifyIdToken('t')).rejects.toMatchObject({ code: 'INVALID_ID_TOKEN' });
        const rejected = bad.entries.find((e) => e.message.includes('token rejected'))!;
        expect(rejected.level).toBe('debug');
        expect(bad.entries.some((e) => e.message.includes('non-auth reason'))).toBe(false);
    });

    it('verifyIdToken reports malformed customAttributes instead of dropping them silently', async () => {
        const { fb, entries } = setup(
            'warn',
            routes([
                [
                    `POST ${IDT_PUBLIC}/accounts:lookup`,
                    () => ({ users: [{ localId: 'u1', email: 'a@b.com', customAttributes: '{oops' }] }),
                ],
            ])
        );
        await expect(fb.auth.verifyIdToken('t')).resolves.toMatchObject({ uid: 'u1' });
        expect(find(entries, 'auth', 'verifyIdToken: ignoring malformed customAttributes')?.level).toBe('warn');
    });

    it('createUser rollback failures are logged, and the original error still wins', async () => {
        const { fb, entries } = setup(
            'warn',
            routes([
                [`POST ${IDT_ADMIN}/accounts`, () => ({ localId: 'u1' })],
                [`PATCH ${FS_DOCS}/users/u1`, () => apiError('write failed', 500)],
                [`POST ${IDT_ADMIN}/accounts:delete`, () => apiError('cannot delete', 500)],
                [`DELETE ${FS_DOCS}/users/u1`, () => ({})],
            ])
        );
        await expect(
            fb.auth.createUser({ email: 'a@b.com', password: 'secret-pass' })
        ).rejects.toMatchObject({ status: 500, message: 'write failed' });
        expect(find(entries, 'auth', 'createUser: follow-up step failed, rolling back')?.level).toBe('warn');
        const orphan = entries.find((e) => e.message.includes('could not delete the auth user'))!;
        expect(orphan.level).toBe('error');
        expect(orphan.data).toMatchObject({ uid: 'u1' });
    });

    const resetRoutes = () =>
        routes([
            [`POST ${IDT_ADMIN}/accounts:lookup`, () => ({ users: [{ localId: 'u1', email: 'a@b.com' }] })],
            [`POST ${IDT_ADMIN}/accounts:update`, () => ({})],
            [`POST ${FS_DOCS}:commit`, () => ({})],
        ]);

    it('emailSender failures are logged; console.error is only the fallback', async () => {
        const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
        const boom = vi.fn().mockRejectedValue(new Error('smtp down'));

        const on = setup('error', resetRoutes(), { emailSender: boom });
        await expect(on.fb.auth.resetUserPassword('u1', 'new-secret-pw')).resolves.toMatchObject({
            emailSent: false,
        });
        expect(on.entries.find((e) => e.message.includes('emailSender threw'))?.level).toBe('error');
        expect(consoleError).not.toHaveBeenCalled();

        const off = setup(undefined, resetRoutes(), { emailSender: boom });
        await off.fb.auth.resetUserPassword('u1', 'new-secret-pw');
        expect(consoleError).toHaveBeenCalledWith('emailSender failed:', expect.any(Error));
    });

    it('an emailSender that returns false is a warning', async () => {
        const { fb, entries } = setup('warn', resetRoutes(), { emailSender: async () => false });
        await fb.auth.resetUserPassword('u1', 'new-secret-pw');
        expect(entries.find((e) => e.message.includes('emailSender returned false'))?.level).toBe('warn');
    });

    it('records the deliberate silent no-op in requestPasswordReset', async () => {
        const { fb, entries } = setup(
            'debug',
            routes([[`POST ${IDT_ADMIN}/accounts:lookup`, () => ({})]])
        );
        await expect(fb.auth.requestPasswordReset('ghost@example.com')).resolves.toBeUndefined();
        const e = entries.find((x) => x.message.includes('no-op, user not found or disabled'))!;
        expect(e).toBeTruthy();
        expect(JSON.stringify(entries)).not.toContain('ghost@example.com');
    });

    it('invalid page tokens keep their cause', async () => {
        const { fb } = setup('error');
        const err: any = await fb.firestore.list('users', { pageToken: '***' }).catch((e) => e);
        expect(err.code).toBe('INVALID_PAGE_TOKEN');
        expect(err.cause).toBeInstanceOf(Error);
    });
});

// ---------------------------------------------------------------------------
describe('safety of the logger itself', () => {
    const okRoutes = routes([[`GET ${FS_DOCS}/users/u1`, () => ({ fields: {} })]]);

    it('a throwing sink never breaks the operation', async () => {
        const { fb } = setup(undefined, okRoutes, {
            logger: {
                level: 'trace',
                sink: () => {
                    throw new Error('sink exploded');
                },
            },
        });
        await expect(fb.firestore.get('users', 'u1')).resolves.toEqual({});
    });

    it('a rejecting async sink does not cause unhandled rejections', async () => {
        const unhandled = vi.fn();
        process.on('unhandledRejection', unhandled);
        const { fb } = setup(undefined, okRoutes, {
            logger: { level: 'debug', sink: async () => Promise.reject(new Error('async sink')) },
        });
        await fb.firestore.get('users', 'u1');
        await new Promise((r) => setTimeout(r, 10));
        process.off('unhandledRejection', unhandled);
        expect(unhandled).not.toHaveBeenCalled();
    });

    it('does not consume the response body that callers read', async () => {
        const { fb } = setup('trace', routes([[`GET ${FS_DOCS}/users/u1`, () => ({ fields: { a: { stringValue: 'x' } } })]]));
        await expect(fb.firestore.get('users', 'u1')).resolves.toEqual({ a: 'x' });
    });

    it('consoleSink maps levels to console methods', () => {
        const spies = {
            error: vi.spyOn(console, 'error').mockImplementation(() => {}),
            warn: vi.spyOn(console, 'warn').mockImplementation(() => {}),
            info: vi.spyOn(console, 'info').mockImplementation(() => {}),
            debug: vi.spyOn(console, 'debug').mockImplementation(() => {}),
        };
        for (const level of ['error', 'warn', 'info', 'debug', 'trace'] as const) {
            consoleSink({ level, scope: 'auth', message: 'm', time: 0 });
        }
        expect(spies.error).toHaveBeenCalledTimes(1);
        expect(spies.warn).toHaveBeenCalledTimes(1);
        expect(spies.info).toHaveBeenCalledTimes(1);
        expect(spies.debug).toHaveBeenCalledTimes(2);
        expect(spies.error.mock.calls[0][0]).toBe('[firebase-edge:auth] ERROR m');
    });

    it('does not evaluate lazy data when the level is filtered out', async () => {
        const sinkSpy = vi.fn();
        const { fb } = setup(undefined, okRoutes, { logger: { level: 'error', sink: sinkSpy } });
        await fb.firestore.get('users', 'u1');
        expect(sinkSpy).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
describe('configFromEnv', () => {
    const ENV = {
        FB_PROJECT_ID: PROJECT_ID,
        FB_CLIENT_EMAIL: 'svc@test-project.iam.gserviceaccount.com',
        FB_PRIVATE_KEY_ID: 'kid-1',
        FB_PRIVATE_KEY: PRIVATE_KEY_PEM,
        FB_API_KEY: API_KEY,
    };

    it('reads FB_LOG_LEVEL (case-insensitive, trimmed)', () => {
        expect(configFromEnv({ ...ENV, FB_LOG_LEVEL: ' DEBUG ' }).logger).toBe('debug');
    });

    it('leaves logging off when unset, and overrides win', () => {
        expect('logger' in configFromEnv(ENV)).toBe(false);
        expect(configFromEnv({ ...ENV, FB_LOG_LEVEL: 'debug' }, { logger: 'error' }).logger).toBe('error');
    });

    it('passes a typo through so it is reported, not silently ignored', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
        createFirebaseEdge({ ...configFromEnv({ ...ENV, FB_LOG_LEVEL: 'verbose' }), fetchFn: createMockFetch().fetchFn });
        expect(warn).toHaveBeenCalledTimes(1);
    });
});

describe('token provider logging', () => {
    it('reports cache hits and misses', async () => {
        const { fb, entries } = setup('debug');
        await fb.getAccessToken('scope-a');
        await fb.getAccessToken('scope-a');
        const msgs = entries.filter((e) => e.scope === 'token').map((e) => e.message);
        expect(msgs).toEqual([
            'token cache miss',
            'importing service-account signing key',
            'access token refreshed',
            'token cache hit',
        ]);
    });
});
