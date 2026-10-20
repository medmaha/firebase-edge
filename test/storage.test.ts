import { describe, expect, it } from 'vitest';
import { FirebaseError } from '../src/errors';
import { createSigner } from '../src/google-auth';
import { createStorage } from '../src/storage';
import { assertObjectName, uriEncode } from '../src/utils.storage';
import {
    BUCKET,
    CLIENT_EMAIL,
    PRIVATE_KEY_PEM,
    PUBLIC_KEY_PEM,
    apiError,
    callsTo,
    jsonResponse,
    makeCtx,
    routes,
} from './helpers';
import { pemToDer } from '../src/utils';

const API = `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o`;
const UPLOAD = `https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o`;
const obj = (name: string, extra: Record<string, unknown> = {}) => ({
    name,
    bucket: BUCKET,
    size: '5',
    contentType: 'text/plain',
    generation: '1',
    timeCreated: '2026-01-01T00:00:00.000Z',
    updated: '2026-01-02T00:00:00.000Z',
    ...extra,
});
const text = (b: unknown) => new TextDecoder().decode(b as Uint8Array);

describe('assertObjectName / uriEncode', () => {
    it('rejects invalid object names', () => {
        for (const bad of ['', '/a', 'a/../b', './a', 'a/./b', 'a\nb']) {
            expect(() => assertObjectName(bad)).toThrow(FirebaseError);
        }
        expect(() => assertObjectName('a/b c/ü.png')).not.toThrow();
    });

    it('encodes per RFC 3986 and optionally keeps slashes', () => {
        expect(uriEncode("a b/c!'()*")).toBe('a%20b%2Fc%21%27%28%29%2A');
        expect(uriEncode('a b/c', false)).toBe('a%20b/c');
    });
});

describe('storage.upload', () => {
    it('sends a multipart upload with metadata and bytes', async () => {
        const { ctx, calls } = makeCtx(
            routes([[`POST ${UPLOAD}`, () => obj('docs/a.txt', { metadata: { owner: 'u1' } })]])
        );
        const result = await createStorage(ctx).upload('docs/a.txt', 'hello', {
            metadata: { owner: 'u1' },
            cacheControl: 'no-cache',
        });

        expect(result).toMatchObject({
            name: 'docs/a.txt',
            size: 5,
            metadata: { owner: 'u1' },
            createdAt: Date.parse('2026-01-01T00:00:00.000Z'),
        });
        const [call] = callsTo(calls, 'POST', UPLOAD);
        expect(call.url).toBe(`${UPLOAD}?uploadType=multipart`);
        expect(call.headers.Authorization).toBe('Bearer test-token');
        expect(call.headers['Content-Type']).toMatch(
            /^multipart\/related; boundary=firebase-edge-/
        );
        const body = text(call.body);
        expect(body).toContain('"name":"docs/a.txt"');
        expect(body).toContain('"cacheControl":"no-cache"');
        expect(body).toContain('"metadata":{"owner":"u1"}');
        expect(body).toContain('Content-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n--');
    });

    it('uses the given content type for binary data and passes ifGenerationMatch', async () => {
        const { ctx, calls } = makeCtx(routes([[`POST ${UPLOAD}`, () => obj('p.png')]]));
        await createStorage(ctx).upload('p.png', new Uint8Array([1, 2, 3]), {
            contentType: 'image/png',
            ifGenerationMatch: 0,
        });
        expect(calls[0].url).toBe(`${UPLOAD}?ifGenerationMatch=0&uploadType=multipart`);
        expect(text(calls[0].body)).toContain('"contentType":"image/png"');
    });

    it('adds a Firebase download token when requested', async () => {
        const { ctx, calls } = makeCtx(routes([[`POST ${UPLOAD}`, () => obj('a.txt')]]));
        const storage = createStorage(ctx);
        await storage.upload('a.txt', 'x', { downloadToken: 'tok-1' });
        await storage.upload('b.txt', 'x', { downloadToken: true });
        expect(text(calls[0].body)).toContain('"firebaseStorageDownloadTokens":"tok-1"');
        expect(text(calls[1].body)).toMatch(/"firebaseStorageDownloadTokens":"[0-9a-f-]{36}"/);
    });

    it('throws error for large file size', async () => {
        const session = 'https://storage.googleapis.com/upload/storage/v1/b/x/o?upload_id=abc';
        const { ctx, calls } = makeCtx(
            routes([
                [
                    `POST ${UPLOAD}`,
                    () => new Response('{}', { status: 200, headers: { Location: session } }),
                ],
                [`PUT ${session}`, () => obj('big.bin', { size: String(9 * 1024 * 1024) })],
            ])
        );
        const big = new Uint8Array(9 * 1024 * 1024);
        await expect(createStorage(ctx).upload('big.bin', big)).rejects.toMatchObject({
            name: 'FirebaseError',
            code: 'INVALID_ARGUMENT',
            message: "Storage uploads are limited to 8 MiB;"
        });
    });

    it('throws FirebaseError with the GCS reason and status on failure', async () => {
        const { ctx } = makeCtx(
            routes([
                [
                    `POST ${UPLOAD}`,
                    () =>
                        apiError('Precondition Failed', 412, {
                            errors: [{ reason: 'conditionNotMet' }],
                        }),
                ],
            ])
        );
        await expect(
            createStorage(ctx).upload('a.txt', 'x', { ifGenerationMatch: 0 })
        ).rejects.toMatchObject({
            name: 'FirebaseError',
            code: 'conditionNotMet',
            status: 412,
        });
    });

    it('throws NOT_FOUND when the bucket is missing and INVALID_ARGUMENT for bad names', async () => {
        const { ctx } = makeCtx(routes([[`POST ${UPLOAD}`, () => apiError('nope', 404)]]));
        await expect(createStorage(ctx).upload('a.txt', 'x')).rejects.toMatchObject({
            code: 'NOT_FOUND',
        });
        await expect(createStorage(ctx).upload('/a.txt', 'x')).rejects.toMatchObject({
            code: 'INVALID_ARGUMENT',
        });
    });
});

describe('storage download / metadata / delete', () => {
    const url = `${API}/${encodeURIComponent('dir/a b.txt')}`;

    it('downloads bytes and returns null when missing', async () => {
        const { ctx, calls } = makeCtx(
            routes([
                [`GET ${url}?alt=media`, () => new Response('hello')],
                [`GET ${API}/missing?alt=media`, () => apiError('Not Found', 404)],
            ])
        );
        const storage = createStorage(ctx);
        expect(text(await storage.download('dir/a b.txt'))).toBe('hello');
        expect(await storage.download('missing')).toBeNull();
        expect(await storage.downloadStream('missing')).toBeNull();
        const stream = await storage.downloadStream('dir/a b.txt');
        expect(await new Response(stream).text()).toBe('hello');
        expect(calls[0].headers.Authorization).toBe('Bearer test-token');
    });

    it('reads metadata, returning null when missing', async () => {
        const { ctx } = makeCtx(
            routes([
                [`GET ${url}`, () => obj('dir/a b.txt', { metadata: { k: 'v' } })],
                [`GET ${API}/missing`, () => apiError('Not Found', 404)],
            ])
        );
        const storage = createStorage(ctx);
        expect(await storage.getMetadata('dir/a b.txt')).toMatchObject({
            size: 5,
            metadata: { k: 'v' },
        });
        expect(await storage.getMetadata('missing')).toBeNull();
    });

    it('patches metadata and throws NOT_FOUND for missing objects', async () => {
        const { ctx, calls } = makeCtx(
            routes([
                [`PATCH ${url}`, () => obj('dir/a b.txt', { cacheControl: 'no-store' })],
                [`PATCH ${API}/missing`, () => apiError('Not Found', 404)],
            ])
        );
        const storage = createStorage(ctx);
        const updated = await storage.updateMetadata('dir/a b.txt', {
            cacheControl: 'no-store',
            metadata: { old: null },
        });
        expect(updated.cacheControl).toBe('no-store');
        expect(calls[0].body).toEqual({ cacheControl: 'no-store', metadata: { old: null } });
        await expect(storage.updateMetadata('missing', {})).rejects.toMatchObject({
            code: 'NOT_FOUND',
        });
    });

    it('deletes objects and treats a missing one as a no-op', async () => {
        const { ctx, calls } = makeCtx(
            routes([
                [`DELETE ${url}`, () => new Response(null, { status: 204 })],
                [`DELETE ${API}/missing`, () => apiError('Not Found', 404)],
            ])
        );
        const storage = createStorage(ctx);
        await storage.delete('dir/a b.txt');
        await storage.delete('missing');
        expect(calls).toHaveLength(2);
    });
});

describe('storage.list', () => {
    it('lists objects and prefixes with paging parameters', async () => {
        const { ctx, calls } = makeCtx(
            routes([
                [
                    `GET ${API}`,
                    () => ({
                        items: [obj('a/1.txt'), obj('a/2.txt')],
                        prefixes: ['a/sub/'],
                        nextPageToken: 'next',
                    }),
                ],
            ])
        );
        const result = await createStorage(ctx).list({
            prefix: 'a/',
            delimiter: '/',
            limit: 2,
            pageToken: 'p',
        });
        expect(result.objects.map((o) => o.name)).toEqual(['a/1.txt', 'a/2.txt']);
        expect(result.prefixes).toEqual(['a/sub/']);
        expect(result.nextPageToken).toBe('next');
        const params = new URL(calls[0].url).searchParams;
        expect(Object.fromEntries(params)).toEqual({
            prefix: 'a/',
            delimiter: '/',
            maxResults: '2',
            pageToken: 'p',
        });
    });

    it('defaults to 100, caps at 1000 and tolerates empty results', async () => {
        const { ctx, calls } = makeCtx(routes([[`GET ${API}`, () => ({})]]));
        const storage = createStorage(ctx);
        expect(await storage.list()).toEqual({
            objects: [],
            prefixes: [],
            nextPageToken: undefined,
        });
        await storage.list({ limit: 5000 });
        expect(new URL(calls[0].url).searchParams.get('maxResults')).toBe('100');
        expect(new URL(calls[1].url).searchParams.get('maxResults')).toBe('1000');
    });
});

describe('storage.getDownloadUrl', () => {
    const url = `${API}/${encodeURIComponent('a b.png')}`;

    it('reuses an existing download token', async () => {
        const { ctx, calls } = makeCtx(
            routes([
                [
                    `GET ${url}`,
                    () => obj('a b.png', { metadata: { firebaseStorageDownloadTokens: 't1,t2' } }),
                ],
            ])
        );
        expect(await createStorage(ctx).getDownloadUrl('a b.png')).toBe(
            `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/a%20b.png?alt=media&token=t1`
        );
        expect(calls).toHaveLength(1);
    });

    it('creates a token when none exists', async () => {
        const { ctx, calls } = makeCtx(
            routes([
                [`GET ${url}`, () => obj('a b.png')],
                [`PATCH ${url}`, (c) => obj('a b.png', { metadata: c.body.metadata })],
            ])
        );
        const result = await createStorage(ctx).getDownloadUrl('a b.png');
        const token = calls[1].body.metadata.firebaseStorageDownloadTokens;
        expect(token).toMatch(/^[0-9a-f-]{36}$/);
        expect(result).toBe(
            `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/a%20b.png?alt=media&token=${token}`
        );
    });

    it('throws NOT_FOUND for missing objects', async () => {
        const { ctx } = makeCtx(routes([[`GET ${API}/gone`, () => apiError('Not Found', 404)]]));
        await expect(createStorage(ctx).getDownloadUrl('gone')).rejects.toMatchObject({
            code: 'NOT_FOUND',
        });
    });
});

describe('storage.signedUrl', () => {
    const now = new Date('2026-03-04T05:06:07.000Z');

    it('builds a V4 URL with the documented query parameters', async () => {
        const { ctx, calls } = makeCtx();
        const result = new URL(
            await createStorage(ctx).signedUrl('dir/a b.txt', {
                now,
                expiresIn: 600,
                responseDisposition: 'attachment',
            })
        );
        expect(result.origin + result.pathname).toBe(
            `https://storage.googleapis.com/${BUCKET}/dir/a%20b.txt`
        );
        const q = result.searchParams;
        expect(q.get('X-Goog-Algorithm')).toBe('GOOG4-RSA-SHA256');
        expect(q.get('X-Goog-Credential')).toBe(
            `${CLIENT_EMAIL}/20260304/auto/storage/goog4_request`
        );
        expect(q.get('X-Goog-Date')).toBe('20260304T050607Z');
        expect(q.get('X-Goog-Expires')).toBe('600');
        expect(q.get('X-Goog-SignedHeaders')).toBe('host');
        expect(q.get('response-content-disposition')).toBe('attachment');
        expect(q.get('X-Goog-Signature')).toMatch(/^[0-9a-f]+$/);
        expect(calls).toHaveLength(0); // signed locally, no network
    });

    it('produces a signature that verifies against the string to sign', async () => {
        const signer = createSigner({
            projectId: 'p',
            clientEmail: CLIENT_EMAIL,
            privateKeyId: 'kid',
            privateKey: PRIVATE_KEY_PEM,
        });
        const { ctx } = makeCtx(undefined, { sign: signer });
        const signed = new URL(
            await createStorage(ctx).signedUrl('a.txt', {
                now,
                contentType: 'text/plain',
                method: 'PUT',
            })
        );

        const canonicalQuery = [...signed.search.slice(1).split('&')]
            .filter((p) => !p.startsWith('X-Goog-Signature='))
            .join('&');
        const canonicalRequest = [
            'PUT',
            `/${BUCKET}/a.txt`,
            canonicalQuery,
            'content-type:text/plain\nhost:storage.googleapis.com',
            '',
            'content-type;host',
            'UNSIGNED-PAYLOAD',
        ].join('\n');
        const hash = Buffer.from(
            await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalRequest))
        ).toString('hex');
        const stringToSign = `GOOG4-RSA-SHA256\n20260304T050607Z\n20260304/auto/storage/goog4_request\n${hash}`;

        const publicKey = await crypto.subtle.importKey(
            'spki',
            pemToDer(PUBLIC_KEY_PEM),
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false,
            ['verify']
        );
        const sig = Uint8Array.from(
            Buffer.from(signed.searchParams.get('X-Goog-Signature')!, 'hex')
        );
        expect(canonicalQuery).toContain('X-Goog-SignedHeaders=content-type%3Bhost');
        expect(
            await crypto.subtle.verify(
                'RSASSA-PKCS1-v1_5',
                publicKey,
                sig,
                new TextEncoder().encode(stringToSign)
            )
        ).toBe(true);
    });

    it('validates expiresIn', async () => {
        const { ctx } = makeCtx();
        const storage = createStorage(ctx);
        for (const expiresIn of [0, -1, 1.5, 604801]) {
            await expect(storage.signedUrl('a.txt', { expiresIn })).rejects.toMatchObject({
                code: 'INVALID_ARGUMENT',
            });
        }
    });
});
