import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { createAuth } from '../src/auth';
import { FirebaseError } from '../src/errors';
import { createFirestore } from '../src/firestore';
import type { EmailSender } from '../src/types';
import {
    API_KEY,
    DOC_NAME,
    FS_DOCS,
    IDT_ADMIN,
    IDT_PUBLIC,
    PRIVATE_KEY_PEM,
    PUBLIC_KEY_PEM,
    PROJECT_ID,
    apiError,
    callsTo,
    commitWrites,
    jsonResponse,
    makeCtx,
    routes,
    type Call,
} from './helpers';

const NOW = Date.parse('2026-01-01T00:00:00.000Z');
const NOW_FIELD = { integerValue: String(NOW) };

const PUBLIC_LOOKUP = `POST ${IDT_PUBLIC}/accounts:lookup`;
const SECURETOKEN_JWKS =
    'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const ADMIN_LOOKUP = `POST ${IDT_ADMIN}/accounts:lookup`;
const ADMIN_UPDATE = `POST ${IDT_ADMIN}/accounts:update`;
const ADMIN_DELETE = `POST ${IDT_ADMIN}/accounts:delete`;
const ADMIN_CREATE = `POST ${IDT_ADMIN}/accounts`;
const PUBLIC_RESET = `POST ${IDT_PUBLIC}/accounts:resetPassword`;
const PUBLIC_OOB = `POST ${IDT_PUBLIC}/accounts:sendOobCode`;
const COMMIT = `POST ${FS_DOCS}:commit`;

type Table = Array<[string, (call: Call) => any]>;

const user = (o: Record<string, unknown> = {}) => ({
    localId: 'u1',
    email: 'ada@example.com',
    disabled: false,
    phoneNumber: '+21 877 675543 54',
    ...o,
});

const testJwk = {
    ...createPublicKey(PUBLIC_KEY_PEM).export({ format: 'jwk' }),
    kid: 'test-key',
    alg: 'RS256',
    use: 'sig',
};

function makeIdToken(claims: Record<string, unknown>) {
    const encode = (value: string | Buffer) => Buffer.from(value).toString('base64url');
    const header = encode(JSON.stringify({ alg: 'RS256', kid: 'test-key' }));
    const payload = encode(JSON.stringify(claims));
    const unsigned = `${header}.${payload}`;
    const signature = sign('RSA-SHA256', Buffer.from(unsigned), createPrivateKey(PRIVATE_KEY_PEM));
    return `${unsigned}.${encode(signature)}`;
}

function localClaims(overrides: Record<string, unknown> = {}) {
    const now = Math.floor(NOW / 1000);
    return {
        iss: `https://securetoken.google.com/${PROJECT_ID}`,
        aud: PROJECT_ID,
        exp: now + 3600,
        iat: now,
        sub: 'u1',
        user_id: 'u1',
        email: 'ada@example.com',
        email_verified: true,
        role: 'admin',
        ...overrides,
    };
}

function jwksResponse(maxAge = 3600) {
    return new Response(JSON.stringify({ keys: [testJwk] }), {
        headers: { 'Cache-Control': `public, max-age=${maxAge}` },
    });
}

function setup(table: Table, emailSender?: EmailSender) {
    const h = makeCtx(routes(table));
    const fs = createFirestore(h.ctx);
    const auth = createAuth(h.ctx, fs, emailSender);
    return { auth, ...h };
}

const find = (calls: Call[], method: string, url: string) =>
    calls.find((c) => c.method === method && c.url === url);

beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
});
afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
describe('verifyIdToken', () => {
    it('verifies locally from the token claims without calling Identity Toolkit', async () => {
        const { auth, calls } = setup([[`GET ${SECURETOKEN_JWKS}`, () => jwksResponse()]]);
        const token = makeIdToken(localClaims());

        await expect(auth.verifyIdToken(token, { mode: 'local' })).resolves.toMatchObject({
            uid: 'u1',
            sub: 'u1',
            email: 'ada@example.com',
            emailVerified: true,
            role: 'admin',
        });
        expect(calls).toHaveLength(1);
        expect(calls[0].url).toBe(SECURETOKEN_JWKS);
    });

    it.each([
        ['expired', localClaims({ exp: Math.floor(NOW / 1000) - 1 })],
        ['wrong audience', localClaims({ aud: 'another-project' })],
        ['wrong issuer', localClaims({ iss: 'https://securetoken.google.com/another-project' })],
        ['future issue time', localClaims({ iat: Math.floor(NOW / 1000) + 1 })],
        ['empty subject', localClaims({ sub: '' })],
    ])('rejects a locally verified token with %s claims', async (_name, claims) => {
        const { auth } = setup([[`GET ${SECURETOKEN_JWKS}`, () => jwksResponse()]]);
        await expect(
            auth.verifyIdToken(makeIdToken(claims), { mode: 'local' })
        ).rejects.toMatchObject({
            code: 'INVALID_ID_TOKEN',
            status: 401,
        });
    });

    it('rejects a tampered local token signature', async () => {
        const { auth } = setup([[`GET ${SECURETOKEN_JWKS}`, () => jwksResponse()]]);
        const token = makeIdToken(localClaims());
        const [header, payload, encodedSignature] = token.split('.');
        const signature = Buffer.from(encodedSignature, 'base64url');
        signature[0] ^= 1;

        await expect(
            auth.verifyIdToken(`${header}.${payload}.${signature.toString('base64url')}`, {
                mode: 'local',
            })
        ).rejects.toMatchObject({ code: 'INVALID_ID_TOKEN', status: 401 });
    });

    it('shares concurrent JWKS fetches and caches keys according to Cache-Control', async () => {
        const { auth, calls } = setup([[`GET ${SECURETOKEN_JWKS}`, () => jwksResponse(10)]]);
        const token = makeIdToken(localClaims());

        await Promise.all(
            Array.from({ length: 5 }, () => auth.verifyIdToken(token, { mode: 'local' }))
        );
        expect(calls.filter((call) => call.url === SECURETOKEN_JWKS)).toHaveLength(1);

        await auth.verifyIdToken(token, { mode: 'local' });
        expect(calls.filter((call) => call.url === SECURETOKEN_JWKS)).toHaveLength(1);

        vi.setSystemTime(NOW + 11_000);
        await auth.verifyIdToken(token, { mode: 'local' });
        expect(calls.filter((call) => call.url === SECURETOKEN_JWKS)).toHaveLength(2);
    });

    it('does not cache JWKS when Cache-Control says no-store', async () => {
        const { auth, calls } = setup([
            [
                `GET ${SECURETOKEN_JWKS}`,
                () =>
                    new Response(JSON.stringify({ keys: [testJwk] }), {
                        headers: { 'Cache-Control': 'no-store' },
                    }),
            ],
        ]);
        const token = makeIdToken(localClaims());

        await auth.verifyIdToken(token, { mode: 'local' });
        await auth.verifyIdToken(token, { mode: 'local' });
        expect(calls.filter((call) => call.url === SECURETOKEN_JWKS)).toHaveLength(2);
    });

    it('returns uid, email and claims, and claims can never override uid/email', async () => {
        const { auth, calls } = setup([
            [
                PUBLIC_LOOKUP,
                () => ({
                    users: [
                        user({
                            emailVerified: true,
                            customAttributes: JSON.stringify({
                                role: 'admin',
                                uid: 'evil',
                                email: 'evil@x.com',
                            }),
                        }),
                    ],
                }),
            ],
        ]);

        await expect(auth.verifyIdToken('id-token')).resolves.toEqual({
            role: 'admin',
            uid: 'u1',
            email: 'ada@example.com',
            emailVerified: true,
        });
        expect(calls[0].url).toContain(`key=${API_KEY}`);
        expect(calls[0].body).toEqual({ idToken: 'id-token' });
        expect(calls[0].headers.Authorization).toBeUndefined(); // public endpoint: no bearer
    });

    it('ignores malformed customAttributes', async () => {
        const { auth } = setup([
            [PUBLIC_LOOKUP, () => ({ users: [user({ customAttributes: '{not json' })] })],
        ]);
        await expect(auth.verifyIdToken('t')).resolves.toMatchObject({ uid: 'u1' });
    });

    it('rejects disabled users with USER_DISABLED (403)', async () => {
        const { auth } = setup([[PUBLIC_LOOKUP, () => ({ users: [user({ disabled: true })] })]]);
        await expect(auth.verifyIdToken('t')).rejects.toMatchObject({
            code: 'USER_DISABLED',
            status: 403,
        });
    });

    it('maps API errors to INVALID_ID_TOKEN (401)', async () => {
        const { auth } = setup([[PUBLIC_LOOKUP, () => apiError('INVALID_ID_TOKEN')]]);
        const err = await auth.verifyIdToken('t').catch((e) => e);
        expect(err).toBeInstanceOf(FirebaseError);
        expect(err).toMatchObject({ code: 'INVALID_ID_TOKEN', status: 401 });
    });

    it('rejects when no user comes back', async () => {
        const { auth } = setup([[PUBLIC_LOOKUP, () => ({ users: [] })]]);
        await expect(auth.verifyIdToken('t')).rejects.toMatchObject({ code: 'INVALID_ID_TOKEN' });
    });
});

// ---------------------------------------------------------------------------
describe('createUser', () => {
    const base = { email: '  Ada@Example.COM ', password: 'secret1', displayName: 'Ada' };
    const happy = (): Table => [
        [ADMIN_CREATE, () => ({ localId: 'u1' })],
        [`PATCH ${FS_DOCS}/users/u1`, () => ({})],
    ];

    it('creates the Auth user and a matching Firestore profile without a role field', async () => {
        const { auth, calls } = setup(happy());

        await expect(auth.createUser(base)).resolves.toEqual({ uid: 'u1' });
        await expect(auth.createUser({ ...base, disabled: true })).resolves.toEqual({ uid: 'u1' });

        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts`)!.body).toEqual({
            email: 'ada@example.com',
            password: 'secret1',
            displayName: 'Ada',
            emailVerified: false,
            disableUser: false,
        });

        const patch = callsTo(calls, 'PATCH', FS_DOCS)[0];
        expect(patch.body.fields).toEqual({
            email: { stringValue: 'ada@example.com' },
            displayName: { stringValue: 'Ada' },
            phoneNumber: { nullValue: null },
            disabled: { booleanValue: false },
            disabledAt: { nullValue: null },
            passwordResetCount: { integerValue: '0' },
            createdAt: NOW_FIELD,
            updatedAt: NOW_FIELD,
        });
        // merge write -> update mask present
        expect(patch.body.fields).not.toHaveProperty('role');
        expect(new URL(patch.url).searchParams.getAll('updateMask.fieldPaths')).not.toContain(
            'role'
        );
    });

    it('does not add a role field when omitted', async () => {
        const { auth, calls } = setup(happy());
        await auth.createUser(base);
        expect(callsTo(calls, 'PATCH', FS_DOCS)[0].body.fields).not.toHaveProperty('role');
    });

    it('includes a trimmed phone number, and omits blank ones', async () => {
        const a = setup(happy());
        await a.auth.createUser({ ...base, phoneNumber: ' +15551234567 ' });
        expect(find(a.calls, 'POST', `${IDT_ADMIN}/accounts`)!.body.phoneNumber).toBe(
            '+15551234567'
        );
        expect(callsTo(a.calls, 'PATCH', FS_DOCS)[0].body.fields.phoneNumber).toEqual({
            stringValue: '+15551234567',
        });

        for (const phoneNumber of ['   ', '', null, undefined]) {
            const b = setup(happy());
            await b.auth.createUser({ ...base, phoneNumber });
            expect(find(b.calls, 'POST', `${IDT_ADMIN}/accounts`)!.body).not.toHaveProperty(
                'phoneNumber'
            );
        }
    });

    it('passes emailVerified through', async () => {
        const { auth, calls } = setup(happy());
        await auth.createUser({ ...base, emailVerified: true });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts`)!.body.emailVerified).toBe(true);
    });

    it('sets custom claims after creating the profile', async () => {
        const { auth, calls } = setup([...happy(), [ADMIN_UPDATE, () => ({})]]);
        await auth.createUser({ ...base, claims: { role: 'admin' } });

        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)!.body).toEqual({
            localId: 'u1',
            customAttributes: '{"role":"admin"}',
        });
    });

    it('rejects weak passwords before touching the network', async () => {
        const { auth, fn } = setup(happy());
        await expect(auth.createUser({ ...base, password: '12345' })).rejects.toMatchObject({
            code: 'WEAK_PASSWORD',
        });
        expect(fn).not.toHaveBeenCalled();
    });

    it('rejects oversized claims before touching the network', async () => {
        const { auth, fn } = setup(happy());
        await expect(
            auth.createUser({ ...base, claims: { big: 'x'.repeat(1000) } })
        ).rejects.toMatchObject({
            code: 'CLAIMS_TOO_LARGE',
        });
        expect(fn).not.toHaveBeenCalled();
    });

    it('propagates Auth errors (e.g. EMAIL_EXISTS) and writes no profile', async () => {
        const { auth, calls } = setup([[ADMIN_CREATE, () => apiError('EMAIL_EXISTS')]]);
        await expect(auth.createUser(base)).rejects.toMatchObject({
            code: 'EMAIL_EXISTS',
            status: 400,
        });
        expect(callsTo(calls, 'PATCH', FS_DOCS)).toHaveLength(0);
    });

    it('fails if Auth returns no localId', async () => {
        const { auth } = setup([[ADMIN_CREATE, () => ({})]]);
        await expect(auth.createUser(base)).rejects.toMatchObject({ code: 'CREATE_USER_FAILED' });
    });

    it('rolls back the Auth user and profile when the Firestore write fails', async () => {
        const { auth, calls } = setup([
            [ADMIN_CREATE, () => ({ localId: 'u1' })],
            [`PATCH ${FS_DOCS}/users/u1`, () => apiError('boom', 500, { status: 'INTERNAL' })],
            [ADMIN_DELETE, () => ({})],
            [`DELETE ${FS_DOCS}/users/u1`, () => ({})],
        ]);

        await expect(auth.createUser(base)).rejects.toMatchObject({ code: 'INTERNAL' });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:delete`)!.body).toEqual({
            localId: 'u1',
        });
        expect(callsTo(calls, 'DELETE', FS_DOCS)).toHaveLength(1);
    });

    it('rolls back when setting claims fails', async () => {
        const { auth, calls } = setup([
            ...happy(),
            [ADMIN_UPDATE, () => apiError('INVALID_CLAIMS')],
            [ADMIN_DELETE, () => ({})],
            [`DELETE ${FS_DOCS}/users/u1`, () => ({})],
        ]);

        await expect(auth.createUser({ ...base, claims: { a: 1 } })).rejects.toMatchObject({
            code: 'INVALID_CLAIMS',
        });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:delete`)).toBeDefined();
        expect(callsTo(calls, 'DELETE', FS_DOCS)).toHaveLength(1);
    });

    it('still surfaces the original error if the rollback itself fails', async () => {
        const { auth } = setup([
            [ADMIN_CREATE, () => ({ localId: 'u1' })],
            [`PATCH ${FS_DOCS}/users/u1`, () => apiError('boom', 500, { status: 'INTERNAL' })],
            [ADMIN_DELETE, () => apiError('DELETE_FAILED', 500)],
            [`DELETE ${FS_DOCS}/users/u1`, () => apiError('DELETE_FAILED', 500)],
        ]);
        await expect(auth.createUser(base)).rejects.toMatchObject({ code: 'INTERNAL' });
    });
    it('ensures either email or phoneNumber is provided for identity', async () => {
        const { auth, calls } = setup([]);

        // providing password alone is not enough
        await expect(auth.createUser({ password: '12345678' })).rejects.toMatchObject({
            code: 'IDENTITY_ASSERTION',
            message: 'Email or phone number required to create user',
        });

        // Invalid identities should fail identity assert
        await expect(
            auth.createUser({ ...base, email: '', phoneNumber: '' })
        ).rejects.toMatchObject({
            code: 'IDENTITY_ASSERTION',
            message: 'Email or phone number required to create user',
        });

        expect(calls).toHaveLength(0);
    });
});

// ---------------------------------------------------------------------------
describe('updateUser', () => {
    const table: Table = [
        [ADMIN_LOOKUP, () => ({ users: [user()] })],
        [COMMIT, () => ({})],
        [ADMIN_UPDATE, () => ({})],
    ];

    it('updates Auth fields and the Firestore profile without storing the password', async () => {
        const { auth, calls } = setup(table);
        const payload = {
            email: 'new@example.com',
            displayName: 'John Doe',
            password: 'new-password',
            disabled: false,
            role: 'admin',
        };

        await expect(auth.updateUser('u1', payload)).resolves.toBeUndefined();

        expect(calls.map((call) => call.url)).toEqual([
            `${IDT_ADMIN}/accounts:lookup`,
            `${FS_DOCS}:commit`,
            `${IDT_ADMIN}/accounts:update`,
        ]);
        expect(commitWrites(calls)[0].update.fields).toEqual({
            email: { stringValue: 'new@example.com' },
            displayName: { stringValue: 'John Doe' },
            disabled: { booleanValue: false },
            role: { stringValue: 'admin' },
        });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)!.body).toEqual({
            localId: 'u1',
            email: 'new@example.com',
            displayName: 'John Doe',
            password: 'new-password',
            disableUser: false,
        });
        expect(payload).toEqual({
            email: 'new@example.com',
            displayName: 'John Doe',
            password: 'new-password',
            disabled: false,
            role: 'admin',
        });
    });

    it('maps disableUser to disabled in Firestore and Auth', async () => {
        const { auth, calls } = setup(table);
        await auth.updateUser('u1', { disableUser: true });

        expect(commitWrites(calls)[0].update.fields).toEqual({
            disabled: { booleanValue: true },
        });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)!.body).toEqual({
            localId: 'u1',
            disableUser: true,
        });
    });

    it('updates only Firestore fields when no Auth fields are provided', async () => {
        const { auth, calls } = setup(table);
        await auth.updateUser('u1', { role: 'member' });

        expect(commitWrites(calls)[0].update.fields).toEqual({
            role: { stringValue: 'member' },
        });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)).toBeUndefined();
    });

    it('rejects unknown users without writing to Firestore', async () => {
        const { auth, calls } = setup([
            [ADMIN_LOOKUP, () => ({ users: [] })],
            [COMMIT, () => ({})],
        ]);

        await expect(auth.updateUser('missing', { role: 'member' })).rejects.toMatchObject({
            code: 'USER_NOT_FOUND',
            status: 404,
        });
        expect(commitWrites(calls)).toHaveLength(0);
    });
});

// ---------------------------------------------------------------------------
describe('setCustomUserClaims', () => {
    it('serializes claims to customAttributes', async () => {
        const { auth, calls } = setup([[ADMIN_UPDATE, () => ({})]]);
        await auth.setCustomUserClaims('u1', { role: 'admin', level: 3 });
        expect(calls[0].body).toEqual({
            localId: 'u1',
            customAttributes: '{"role":"admin","level":3}',
        });
    });

    it('measures the 1000 byte limit in bytes, not characters', async () => {
        const { auth, fn } = setup([[ADMIN_UPDATE, () => ({})]]);
        // 'é' is 2 bytes: 600 chars => 1200 bytes
        await expect(auth.setCustomUserClaims('u1', { v: 'é'.repeat(600) })).rejects.toMatchObject({
            code: 'CLAIMS_TOO_LARGE',
        });
        expect(fn).not.toHaveBeenCalled();
    });

    it('accepts claims right under the limit', async () => {
        const { auth } = setup([[ADMIN_UPDATE, () => ({})]]);
        await expect(
            auth.setCustomUserClaims('u1', { v: 'x'.repeat(900) })
        ).resolves.toBeUndefined();
    });

    it('propagates API errors', async () => {
        const { auth } = setup([[ADMIN_UPDATE, () => apiError('USER_NOT_FOUND')]]);
        await expect(auth.setCustomUserClaims('nope', {})).rejects.toMatchObject({
            code: 'USER_NOT_FOUND',
        });
    });
});

// ---------------------------------------------------------------------------
describe('disableUser', () => {
    const table = (existing: Record<string, unknown> | null): Table => [
        [ADMIN_LOOKUP, () => ({ users: existing ? [existing] : [] })],
        [ADMIN_UPDATE, () => ({})],
        [COMMIT, () => ({})],
    ];

    it('toggles an enabled user to disabled and mirrors it to Firestore', async () => {
        const { auth, calls } = setup(table(user({ disabled: false })));

        await expect(auth.disableUser('u1')).resolves.toEqual({ uid: 'u1', disabled: true });

        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)!.body).toEqual({
            localId: 'u1',
            disableUser: true,
        });
        const [write] = commitWrites(calls);
        expect(write.update.name).toBe(DOC_NAME('users/u1'));
        expect(write.update.fields).toEqual({
            updatedAt: NOW_FIELD,
            disabled: { booleanValue: true },
            disabledAt: NOW_FIELD,
        });
    });

    it('toggles a disabled user back on and clears disabledAt', async () => {
        const { auth, calls } = setup(table(user({ disabled: true })));

        await expect(auth.disableUser('u1')).resolves.toEqual({ uid: 'u1', disabled: false });

        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)!.body.disableUser).toBe(false);
        expect(commitWrites(calls)[0].update.fields).toEqual({
            updatedAt: NOW_FIELD,
            disabled: { booleanValue: false },
            disabledAt: { nullValue: null },
        });
    });

    it('uses the explicit value and skips the lookup', async () => {
        const { auth, calls } = setup(table(null));
        await expect(auth.disableUser('u1', true)).resolves.toEqual({ uid: 'u1', disabled: true });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:lookup`)).toBeUndefined();

        await expect(auth.disableUser('u1', false)).resolves.toEqual({
            uid: 'u1',
            disabled: false,
        });
    });

    it('fails with USER_NOT_FOUND when toggling an unknown user', async () => {
        const { auth, calls } = setup(table(null));
        await expect(auth.disableUser('ghost')).rejects.toMatchObject({
            code: 'USER_NOT_FOUND',
            status: 404,
        });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)).toBeUndefined();
    });

    it('does not touch Firestore if the Auth update fails', async () => {
        const { auth, calls } = setup([
            [ADMIN_LOOKUP, () => ({ users: [user()] })],
            [ADMIN_UPDATE, () => apiError('USER_NOT_FOUND')],
        ]);
        await expect(auth.disableUser('u1')).rejects.toMatchObject({ code: 'USER_NOT_FOUND' });
        expect(commitWrites(calls)).toHaveLength(0);
    });
});

// ---------------------------------------------------------------------------
describe('deleteUserPermanent', () => {
    it('deletes the auth user and mirrors it in Firestore', async () => {
        const { auth, calls } = setup([
            [`DELETE ${FS_DOCS}/users/u1`, () => ({})],
            [ADMIN_DELETE, () => ({})],
        ]);

        await expect(auth.deleteUserPermanent('u1')).resolves.toMatchObject({ success: true });

        expect(find(calls, 'DELETE', `${FS_DOCS}/users/u1`)).toBeTruthy();
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:delete`)).toBeTruthy();
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:delete`)!.body.localId).toEqual('u1');

        // firestore
        expect(calls[0].method).toEqual('DELETE');
        expect(calls[0].url.includes('u1')).toBe(true);

        // // auth
        expect(calls[1].method).toEqual('POST');
        expect(calls[1].body).toMatchObject({ localId: 'u1' });
    });

    it('ignores USER_NOT_FOUND error if user already deleted', async () => {
        const { auth, calls } = setup([
            [`DELETE ${FS_DOCS}/users/u1`, () => ({})],
            [
                ADMIN_DELETE,
                () => {
                    throw new Error('USER_NOT_FOUND');
                },
            ],
        ]);

        await expect(auth.deleteUserPermanent('u1')).resolves.toEqual({ success: true });

        //
        expect(find(calls, 'DELETE', `${FS_DOCS}/users/u1`)).toBeTruthy();
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:delete`)).toBeTruthy();
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:delete`)!.body.localId).toEqual('u1');
    });

    it('test ignores auth user deletion if firestore fails', async () => {
        const allUsers = [user()];
        const { auth, calls } = setup([
            [
                ADMIN_DELETE,
                () => {
                    allUsers.pop();
                },
            ],
            [
                `DELETE ${FS_DOCS}/users/u1`,
                () => {
                    throw new Error('INTERNAL_TEST_ERROR');
                },
            ],
        ]);

        await expect(auth.deleteUserPermanent('u1')).rejects.toSatisfy((e) =>
            String(e).includes('INTERNAL_TEST_ERROR')
        );

        //
        expect(allUsers.length).toBe(1);
        expect(allUsers[0].email).toBe(user().email);

        expect(find(calls, 'DELETE', `${FS_DOCS}/users/u1`)).toBeTruthy();
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:delete`)).toBeFalsy(); // should not be called
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:delete`)?.body?.localId).toBeUndefined();
    });
});

// ---------------------------------------------------------------------------
describe('resetUserPassword', () => {
    const table = (existing: Record<string, unknown> | null): Table => [
        [ADMIN_LOOKUP, () => ({ users: existing ? [existing] : [] })],
        [ADMIN_UPDATE, () => ({})],
        [COMMIT, () => ({})],
    ];

    it('sets the password, revokes sessions, records the reset and emails the user', async () => {
        const sender = vi.fn<EmailSender>(async () => true);
        const { auth, calls } = setup(table(user()), sender);

        await expect(auth.resetUserPassword('u1', 'brand-new-pw')).resolves.toEqual({
            uid: 'u1',
            emailSent: true,
        });

        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)!.body).toEqual({
            localId: 'u1',
            password: 'brand-new-pw',
            validSince: String(Math.floor(NOW / 1000)),
        });

        const [write] = commitWrites(calls);
        expect(write.update.fields).toEqual({ updatedAt: NOW_FIELD, passwordResetAt: NOW_FIELD });
        expect(write.updateTransforms).toEqual([
            { fieldPath: 'passwordResetCount', increment: { integerValue: '1' } },
        ]);

        expect(sender).toHaveBeenCalledTimes(1);
        expect(sender.mock.calls[0][0]).toMatchObject({
            to: 'ada@example.com',
            subject: 'Your password was reset',
        });
    });

    it('rejects weak passwords before any network call', async () => {
        const { auth, fn } = setup(table(user()));
        await expect(auth.resetUserPassword('u1', 'abc')).rejects.toMatchObject({
            code: 'WEAK_PASSWORD',
        });
        expect(fn).not.toHaveBeenCalled();
    });

    it('fails with USER_NOT_FOUND and changes nothing', async () => {
        const { auth, calls } = setup(table(null));
        await expect(auth.resetUserPassword('ghost', 'password1')).rejects.toMatchObject({
            code: 'USER_NOT_FOUND',
            status: 404,
        });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:update`)).toBeUndefined();
    });

    it('reports emailSent=false when no sender is configured', async () => {
        const { auth } = setup(table(user()));
        await expect(auth.resetUserPassword('u1', 'password1')).resolves.toEqual({
            uid: 'u1',
            emailSent: false,
        });
    });

    it('reports emailSent=false when the sender returns false', async () => {
        const { auth } = setup(table(user()), async () => false);
        expect((await auth.resetUserPassword('u1', 'password1')).emailSent).toBe(false);
    });

    it('treats a void return from the sender as sent', async () => {
        const { auth } = setup(table(user()), async () => {});
        expect((await auth.resetUserPassword('u1', 'password1')).emailSent).toBe(true);
    });

    it('does not fail the reset when the sender throws', async () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const { auth } = setup(table(user()), async () => {
            throw new Error('smtp down');
        });

        await expect(auth.resetUserPassword('u1', 'password1')).resolves.toEqual({
            uid: 'u1',
            emailSent: false,
        });
        expect(errorSpy).toHaveBeenCalled();
    });

    it('skips the email for users without an address', async () => {
        const sender = vi.fn<EmailSender>(async () => true);
        const { auth } = setup(table(user({ email: undefined })), sender);
        expect((await auth.resetUserPassword('u1', 'password1')).emailSent).toBe(false);
        expect(sender).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
describe('requestPasswordReset', () => {
    it('asks Firebase to send the email (normalized address) and records it', async () => {
        const { auth, calls } = setup([
            [ADMIN_LOOKUP, () => ({ users: [user()] })],
            [PUBLIC_OOB, () => ({ email: 'ada@example.com' })],
            [COMMIT, () => ({})],
        ]);

        await auth.requestPasswordReset('  Ada@Example.com ', 'https://app.example.com/login');

        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:lookup`)!.body).toEqual({
            email: ['ada@example.com'],
        });
        const oob = calls.find((c) => c.url.startsWith(`${IDT_PUBLIC}/accounts:sendOobCode`))!;
        expect(oob.body).toEqual({
            requestType: 'PASSWORD_RESET',
            email: 'ada@example.com',
            continueUrl: 'https://app.example.com/login',
        });
        expect(commitWrites(calls)[0].update.fields).toEqual({
            updatedAt: NOW_FIELD,
            passwordResetLinkSentAt: NOW_FIELD,
        });
        expect(commitWrites(calls)[0].update.name).toBe(DOC_NAME('users/u1'));
    });

    it('omits continueUrl when not provided', async () => {
        const { auth, calls } = setup([
            [ADMIN_LOOKUP, () => ({ users: [user()] })],
            [PUBLIC_OOB, () => ({})],
            [COMMIT, () => ({})],
        ]);
        await auth.requestPasswordReset('ada@example.com');
        const oob = calls.find((c) => c.url.startsWith(`${IDT_PUBLIC}/accounts:sendOobCode`))!;
        expect(oob.body).not.toHaveProperty('continueUrl');
    });

    it('silently does nothing for unknown emails (no enumeration)', async () => {
        const { auth, calls } = setup([[ADMIN_LOOKUP, () => ({ users: [] })]]);
        await expect(auth.requestPasswordReset('nobody@example.com')).resolves.toBeUndefined();
        expect(calls).toHaveLength(1);
    });

    it('silently does nothing for disabled users', async () => {
        const { auth, calls } = setup([
            [ADMIN_LOOKUP, () => ({ users: [user({ disabled: true })] })],
        ]);
        await expect(auth.requestPasswordReset('ada@example.com')).resolves.toBeUndefined();
        expect(calls).toHaveLength(1);
    });

    it('swallows EMAIL_NOT_FOUND from Firebase and writes nothing', async () => {
        const { auth, calls } = setup([
            [ADMIN_LOOKUP, () => ({ users: [user()] })],
            [PUBLIC_OOB, () => apiError('EMAIL_NOT_FOUND')],
        ]);
        await expect(auth.requestPasswordReset('ada@example.com')).resolves.toBeUndefined();
        expect(commitWrites(calls)).toHaveLength(0);
    });

    it('rethrows other Firebase errors', async () => {
        const { auth } = setup([
            [ADMIN_LOOKUP, () => ({ users: [user()] })],
            [PUBLIC_OOB, () => apiError('TOO_MANY_ATTEMPTS_TRY_LATER : slow down', 400)],
        ]);
        await expect(auth.requestPasswordReset('ada@example.com')).rejects.toMatchObject({
            code: 'TOO_MANY_ATTEMPTS_TRY_LATER',
        });
    });
});

// ---------------------------------------------------------------------------
describe('verifyPasswordResetCode', () => {
    const table = (
        reset: Record<string, unknown> | Response,
        existing: Record<string, unknown> | null = user()
    ): Table => [
        [PUBLIC_RESET, () => reset],
        [ADMIN_LOOKUP, () => ({ users: existing ? [existing] : [] })],
        [COMMIT, () => ({})],
    ];

    it('returns the email and records the verification', async () => {
        const { auth, calls } = setup(
            table({ email: 'Ada@Example.com', requestType: 'PASSWORD_RESET' })
        );

        await expect(auth.verifyPasswordResetCode('oob123')).resolves.toEqual({
            email: 'Ada@Example.com',
        });

        const reset = calls.find((c) => c.url.startsWith(`${IDT_PUBLIC}/accounts:resetPassword`))!;
        expect(reset.body).toEqual({ oobCode: 'oob123' });
        expect(find(calls, 'POST', `${IDT_ADMIN}/accounts:lookup`)!.body).toEqual({
            email: ['ada@example.com'],
        });
        expect(commitWrites(calls)[0].update.fields).toEqual({
            updatedAt: NOW_FIELD,
            passwordResetLinkVerifiedAt: NOW_FIELD,
        });
    });

    it('accepts responses without a requestType', async () => {
        const { auth } = setup(table({ email: 'ada@example.com' }));
        await expect(auth.verifyPasswordResetCode('c')).resolves.toEqual({
            email: 'ada@example.com',
        });
    });

    it('rejects codes that are not password-reset codes', async () => {
        const { auth, calls } = setup(
            table({ email: 'ada@example.com', requestType: 'VERIFY_EMAIL' })
        );
        await expect(auth.verifyPasswordResetCode('c')).rejects.toMatchObject({
            code: 'INVALID_OOB_CODE',
        });
        expect(commitWrites(calls)).toHaveLength(0);
    });

    it('propagates expired / invalid code errors', async () => {
        const { auth } = setup(table(apiError('EXPIRED_OOB_CODE')));
        await expect(auth.verifyPasswordResetCode('c')).rejects.toMatchObject({
            code: 'EXPIRED_OOB_CODE',
        });
    });

    it('still returns the email when no profile exists', async () => {
        const { auth, calls } = setup(table({ email: 'ada@example.com' }, null));
        await expect(auth.verifyPasswordResetCode('c')).resolves.toEqual({
            email: 'ada@example.com',
        });
        expect(commitWrites(calls)).toHaveLength(0);
    });
});

// ---------------------------------------------------------------------------
describe('confirmPasswordReset', () => {
    const table = (): Table => [
        [PUBLIC_RESET, () => ({ email: 'ada@example.com', requestType: 'PASSWORD_RESET' })],
        [ADMIN_LOOKUP, () => ({ users: [user()] })],
        [COMMIT, () => ({})],
    ];

    it('applies the new password and records passwordResetConfirmedAt', async () => {
        const { auth, calls } = setup(table());

        await expect(auth.confirmPasswordReset('oob123', 'new-password')).resolves.toEqual({
            email: 'ada@example.com',
        });

        const reset = calls.find((c) => c.url.startsWith(`${IDT_PUBLIC}/accounts:resetPassword`))!;
        expect(reset.body).toEqual({ oobCode: 'oob123', newPassword: 'new-password' });
    });

    it('writes passwordResetConfirmedAt (and not the link-sent field)', async () => {
        const { auth, calls } = setup(table());
        await auth.confirmPasswordReset('oob123', 'new-password');

        const fields = commitWrites(calls)[0].update.fields;
        expect(fields).toEqual({ updatedAt: NOW_FIELD, passwordResetConfirmedAt: NOW_FIELD });
        expect(fields).not.toHaveProperty('passwordResetLinkSentAt');
    });

    it('rejects weak passwords before any network call', async () => {
        const { auth, fn } = setup(table());
        await expect(auth.confirmPasswordReset('c', '123')).rejects.toMatchObject({
            code: 'WEAK_PASSWORD',
        });
        expect(fn).not.toHaveBeenCalled();
    });

    it('propagates invalid code errors without writing', async () => {
        const { auth, calls } = setup([[PUBLIC_RESET, () => apiError('INVALID_OOB_CODE')]]);
        await expect(auth.confirmPasswordReset('bad', 'new-password')).rejects.toMatchObject({
            code: 'INVALID_OOB_CODE',
        });
        expect(commitWrites(calls)).toHaveLength(0);
    });
});

// ---------------------------------------------------------------------------
describe('error parsing', () => {
    it('splits "CODE : detail" messages into code and full message', async () => {
        const { auth } = setup([
            [
                ADMIN_UPDATE,
                () => apiError('WEAK_PASSWORD : Password should be at least 6 characters'),
            ],
        ]);
        const err = await auth.setCustomUserClaims('u1', {}).catch((e) => e);
        expect(err).toBeInstanceOf(FirebaseError);
        expect(err.code).toBe('WEAK_PASSWORD');
        expect(err.message).toBe('WEAK_PASSWORD : Password should be at least 6 characters');
    });

    it('falls back to a status-based message for non-JSON failures', async () => {
        const { auth } = setup([
            [ADMIN_UPDATE, () => new Response('<html>bad gateway</html>', { status: 502 })],
        ]);
        await expect(auth.setCustomUserClaims('u1', {})).rejects.toMatchObject({
            status: 502,
            message: 'Identity Toolkit request failed (502)',
        });
    });

    it('treats a 200 response containing an error object as a failure', async () => {
        const { auth } = setup([
            [ADMIN_UPDATE, () => jsonResponse({ error: { message: 'SOMETHING' } }, 200)],
        ]);
        await expect(auth.setCustomUserClaims('u1', {})).rejects.toMatchObject({
            code: 'SOMETHING',
        });
    });
});
