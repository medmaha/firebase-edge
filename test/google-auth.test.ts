import { afterEach, describe, expect, it, vi } from 'vitest';
import { createTokenProvider } from '../src/google-auth';
import { pemToDer } from '../src/utils';
import {
    PRIVATE_KEY_PEM,
    PUBLIC_KEY_PEM,
    TOKEN_URL,
    apiError,
    b64urlToBytes,
    b64urlToJson,
    createMockFetch,
    jsonResponse,
} from './helpers';

const SA = {
    projectId: 'test-project',
    clientEmail: 'svc@test-project.iam.gserviceaccount.com',
    privateKey: PRIVATE_KEY_PEM,
    privateKeyId: 'kid-1',
};

afterEach(() => vi.useRealTimers());

describe('createTokenProvider', () => {
    it('requests a token with a valid RS256-signed JWT assertion', async () => {
        const { fetchFn, calls } = createMockFetch();
        const token = await createTokenProvider(SA, fetchFn)('scope-a');

        expect(token).toBe('test-token-1');
        expect(calls).toHaveLength(1);
        expect(calls[0].url).toBe(TOKEN_URL);
        expect(calls[0].method).toBe('POST');
        expect(calls[0].headers['Content-Type']).toBe('application/x-www-form-urlencoded');

        const params = new URLSearchParams(calls[0].body);
        expect(params.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');

        const [h, p, s] = params.get('assertion')!.split('.');
        expect(b64urlToJson(h)).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'kid-1' });

        const payload = b64urlToJson(p);
        expect(payload.iss).toBe(SA.clientEmail);
        expect(payload.scope).toBe('scope-a');
        expect(payload.aud).toBe(TOKEN_URL);
        expect(payload.exp - payload.iat).toBe(3600);
        expect(Math.abs(payload.iat - Date.now() / 1000)).toBeLessThan(5);

        const publicKey = await crypto.subtle.importKey(
            'spki',
            pemToDer(PUBLIC_KEY_PEM),
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['verify']
        );
        const valid = await crypto.subtle.verify(
            'RSASSA-PKCS1-v1_5',
            publicKey,
            b64urlToBytes(s) as any,
            new TextEncoder().encode(`${h}.${p}`)
        );
        expect(valid).toBe(true);
    });

    it('caches tokens per scope', async () => {
        const { fetchFn, fn } = createMockFetch();
        const getToken = createTokenProvider(SA, fetchFn);

        const a1 = await getToken('scope-a');
        const a2 = await getToken('scope-a');
        const b1 = await getToken('scope-b');

        expect(a1).toBe(a2);
        expect(b1).not.toBe(a1);
        expect(fn).toHaveBeenCalledTimes(2);
    });

    it('shares one request between concurrent callers', async () => {
        const { fetchFn, fn } = createMockFetch();
        const getToken = createTokenProvider(SA, fetchFn);

        const tokens = await Promise.all(Array.from({ length: 5 }, () => getToken('scope-a')));

        expect(new Set(tokens).size).toBe(1);
        expect(fn).toHaveBeenCalledTimes(1);
    });

    it('refreshes the token 60s before it expires', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        const t0 = Date.parse('2026-01-01T00:00:00Z');
        vi.setSystemTime(t0);

        const { fetchFn, fn } = createMockFetch(); // expires_in = 3600
        const getToken = createTokenProvider(SA, fetchFn);

        expect(await getToken('s')).toBe('test-token-1');

        vi.setSystemTime(t0 + 3539_000); // inside the 3540s window
        expect(await getToken('s')).toBe('test-token-1');
        expect(fn).toHaveBeenCalledTimes(1);

        vi.setSystemTime(t0 + 3541_000); // past it
        expect(await getToken('s')).toBe('test-token-2');
        expect(fn).toHaveBeenCalledTimes(2);
    });

    it('throws on a failed token response and recovers on the next call', async () => {
        let n = 0;
        const { fetchFn } = createMockFetch((call) =>
            call.url === TOKEN_URL && n++ === 0
                ? jsonResponse({ error: 'invalid_grant' }, 400)
                : undefined
        );
        const getToken = createTokenProvider(SA, fetchFn);

        await expect(getToken('s')).rejects.toThrow(/Failed to get access token.*invalid_grant/);
        await expect(getToken('s')).resolves.toBe('test-token-1');
    });

    it('rejects when the response has no access_token', async () => {
        const { fetchFn } = createMockFetch(() => ({ expires_in: 3600 }));
        await expect(createTokenProvider(SA, fetchFn)('s')).rejects.toThrow(
            /Failed to get access token/
        );
    });

    it('rejects an unusable private key and keeps rejecting instead of caching the failure', async () => {
        const { fetchFn, fn } = createMockFetch();
        const getToken = createTokenProvider({ ...SA, privateKey: 'not a key' }, fetchFn);

        await expect(getToken('s')).rejects.toThrow();
        await expect(getToken('s')).rejects.toThrow();
        expect(fn).not.toHaveBeenCalled();
    });

    it('keeps separate caches per provider instance', async () => {
        const { fetchFn, fn } = createMockFetch(() => undefined);
        await createTokenProvider(SA, fetchFn)('s');
        await createTokenProvider(SA, fetchFn)('s');
        expect(fn).toHaveBeenCalledTimes(2);
    });

    it('surfaces API errors from the token endpoint', async () => {
        const { fetchFn } = createMockFetch(() => apiError('boom', 500));
        await expect(createTokenProvider(SA, fetchFn)('s')).rejects.toThrow(/boom/);
    });
});
