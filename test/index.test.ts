import { afterEach, describe, expect, it, vi } from 'vitest';
import { FirebaseError, configFromEnv, createFirebaseEdge, generateDocId, resendEmailSender } from '../src';
import {
  API_KEY,
  DATABASE_NAME,
  FS_DOCS,
  IDT_ADMIN,
  IDT_PUBLIC,
  PRIVATE_KEY_PEM,
  PROJECT_ID,
  TOKEN_URL,
  apiError,
  callsTo,
  createMockFetch,
  routes,
} from './helpers';

const config = (extra: Record<string, unknown> = {}) => ({
  projectId: PROJECT_ID,
  clientEmail: 'svc@test-project.iam.gserviceaccount.com',
  privateKeyId: 'kid-1',
  privateKey: PRIVATE_KEY_PEM,
  apiKey: API_KEY,
  databaseName: DATABASE_NAME,
  ...extra,
});

const ENV = {
  FB_PROJECT_ID: PROJECT_ID,
  FB_CLIENT_EMAIL: 'svc@test-project.iam.gserviceaccount.com',
  FB_PRIVATE_KEY_ID: 'kid-1',
  FB_PRIVATE_KEY: PRIVATE_KEY_PEM,
  FB_API_KEY: API_KEY,
};

afterEach(() => vi.unstubAllGlobals());

describe('public exports', () => {
  it('exposes the documented API', () => {
    expect(typeof createFirebaseEdge).toBe('function');
    expect(typeof configFromEnv).toBe('function');
    expect(typeof generateDocId).toBe('function');
    expect(typeof resendEmailSender).toBe('function');
    expect(new FirebaseError('X')).toBeInstanceOf(Error);
  });

  it('exposes auth, firestore, storage and getAccessToken on the client', () => {
    const fb = createFirebaseEdge(config({ fetchFn: createMockFetch().fetchFn }) as any);
    expect(Object.keys(fb).sort()).toEqual(['auth', 'firestore', 'getAccessToken', 'storage']);
    expect(Object.keys(fb.auth).sort()).toEqual([
      'confirmPasswordReset',
      'createUser',
      'deleteUserPermanent',
      'disableUser',
      'requestPasswordReset',
      'resetUserPassword',
      'setCustomUserClaims',
      'updateUser',
      'verifyIdToken',
      'verifyPasswordResetCode',
    ]);
    expect(Object.keys(fb.firestore).sort()).toEqual([
      'delete',
      'get',
      'list',
      'set',
      'update',
    ]);
    expect(Object.keys(fb.storage).sort()).toEqual([
      'bucket',
      'delete',
      'download',
      'downloadStream',
      'getDownloadUrl',
      'getMetadata',
      'list',
      'signedUrl',
      'updateMetadata',
      'upload',
    ]);
  });

  it('defaults the storage bucket and honours storageBucket', () => {
    const fetchFn = createMockFetch().fetchFn;
    expect(createFirebaseEdge(config({ fetchFn }) as any).storage.bucket).toBe(
      `${PROJECT_ID}.firebasestorage.app`
    );
    expect(
      createFirebaseEdge(config({ fetchFn, storageBucket: 'custom.appspot.com' }) as any).storage.bucket
    ).toBe('custom.appspot.com');
  });
});

describe('createFirebaseEdge', () => {
  it('lists every missing config value', () => {
    expect(() => createFirebaseEdge({} as any)).toThrow(
      'createFirebaseEdge: missing config values: projectId, clientEmail, privateKey, privateKeyId, apiKey'
    );
  });

  it('lists only the ones that are missing', () => {
    expect(() => createFirebaseEdge(config({ apiKey: '', privateKeyId: undefined }) as any)).toThrow(
      /missing config values: privateKeyId, apiKey$/
    );
  });

  it('accepts a private key with escaped newlines and wrapping quotes', async () => {
    const mangled = `"${PRIVATE_KEY_PEM.replace(/\n/g, '\\n')}"`;
    const { fetchFn, calls } = createMockFetch();
    const fb = createFirebaseEdge(config({ privateKey: mangled, fetchFn }) as any);

    await expect(fb.getAccessToken('scope')).resolves.toBe('test-token-1');
    expect(calls[0].url).toBe(TOKEN_URL);
  });

  it('defaults to global fetch when none is supplied', async () => {
    const { fetchFn, calls } = createMockFetch();
    vi.stubGlobal('fetch', fetchFn);

    const fb = createFirebaseEdge(config() as any);
    await fb.getAccessToken('scope');
    expect(calls).toHaveLength(1);
  });

  it('keeps clients isolated from each other', async () => {
    const a = createMockFetch();
    const b = createMockFetch();
    const fbA = createFirebaseEdge(config({ fetchFn: a.fetchFn }) as any);
    const fbB = createFirebaseEdge(config({ fetchFn: b.fetchFn }) as any);

    await fbA.getAccessToken('s');
    await fbB.getAccessToken('s');
    expect(a.calls).toHaveLength(1);
    expect(b.calls).toHaveLength(1);
  });

  it.each([
    [undefined, 'users'],
    ['members', 'members'],
  ])('usersCollection=%s writes profiles to "%s"', async (usersCollection, expected) => {
    const { fetchFn, calls } = createMockFetch(
      routes([
        [`POST ${IDT_ADMIN}/accounts`, () => ({ localId: 'u1' })],
        [`PATCH ${FS_DOCS}/${expected}/u1`, () => ({})],
      ])
    );
    const fb = createFirebaseEdge(config({ fetchFn, usersCollection }) as any);

    await fb.auth.createUser({ email: 'a@b.co', password: 'secret1', displayName: 'A' });
    expect(callsTo(calls, 'PATCH', `${FS_DOCS}/${expected}/u1`)).toHaveLength(1);
  });

  it('shares one OAuth token per scope across auth and firestore calls', async () => {
    const { fetchFn, calls } = createMockFetch(
      routes([
        [`POST ${IDT_ADMIN}/accounts:update`, () => ({})],
        [`PATCH ${FS_DOCS}/c/d`, () => ({})],
      ])
    );
    const fb = createFirebaseEdge(config({ fetchFn }) as any);

    await fb.auth.setCustomUserClaims('u1', { a: 1 });
    await fb.auth.setCustomUserClaims('u1', { a: 2 });
    await fb.firestore.set('c', 'd', { x: 1 });
    await fb.firestore.set('c', 'd', { x: 2 });

    // identity scope + datastore scope = 2 token requests total
    expect(callsTo(calls, 'POST', TOKEN_URL)).toHaveLength(2);
    const bearer = calls.find((c) => c.url === `${IDT_ADMIN}/accounts:update`)!.headers.Authorization;
    expect(bearer).toMatch(/^Bearer test-token-\d$/);
  });

  it('uses the right scope for each API', async () => {
    const { fetchFn, calls } = createMockFetch(
      routes([
        [`POST ${IDT_ADMIN}/accounts:update`, () => ({})],
        [`PATCH ${FS_DOCS}/c/d`, () => ({})],
      ])
    );
    const fb = createFirebaseEdge(config({ fetchFn }) as any);
    await fb.auth.setCustomUserClaims('u1', {});
    await fb.firestore.set('c', 'd', { x: 1 });

    const scopes = callsTo(calls, 'POST', TOKEN_URL).map((c) => {
      const jwt = new URLSearchParams(c.body).get('assertion')!;
      return JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).scope;
    });
    expect(scopes.sort()).toEqual([
      'https://www.googleapis.com/auth/datastore',
      'https://www.googleapis.com/auth/identitytoolkit',
    ]);
  });

  it('wires the configured emailSender into resetUserPassword', async () => {
    const sender = vi.fn(async () => true);
    const { fetchFn } = createMockFetch(
      routes([
        [`POST ${IDT_ADMIN}/accounts:lookup`, () => ({ users: [{ localId: 'u1', email: 'a@b.co' }] })],
        [`POST ${IDT_ADMIN}/accounts:update`, () => ({})],
        [`POST ${FS_DOCS}:commit`, () => ({})],
      ])
    );
    const fb = createFirebaseEdge(config({ fetchFn, emailSender: sender }) as any);

    await expect(fb.auth.resetUserPassword('u1', 'password1')).resolves.toEqual({ uid: 'u1', emailSent: true });
    expect(sender).toHaveBeenCalledWith(expect.objectContaining({ to: 'a@b.co' }));
  });

  it('end to end: verifyIdToken hits the public endpoint with the api key', async () => {
    const { fetchFn, calls } = createMockFetch(
      routes([[`POST ${IDT_PUBLIC}/accounts:lookup`, () => ({ users: [{ localId: 'u9', email: 'z@z.co' }] })]])
    );
    const fb = createFirebaseEdge(config({ fetchFn }) as any);

    await expect(fb.auth.verifyIdToken('tok')).resolves.toMatchObject({ uid: 'u9' });
    expect(callsTo(calls, 'POST', TOKEN_URL)).toHaveLength(0); // no service-account token needed
    expect(calls[0].url).toBe(`${IDT_PUBLIC}/accounts:lookup?key=${API_KEY}`);
  });
});

describe('configFromEnv', () => {
  it('maps the FB_* environment variables', () => {
    expect(configFromEnv(ENV)).toMatchObject({
      projectId: PROJECT_ID,
      clientEmail: 'svc@test-project.iam.gserviceaccount.com',
      privateKeyId: 'kid-1',
      privateKey: PRIVATE_KEY_PEM,
      apiKey: API_KEY,
    });
  });

  it('reads FB_STORAGE_BUCKET when set', () => {
    expect(configFromEnv(ENV).storageBucket).toBeUndefined();
    expect(configFromEnv({ ...ENV, FB_STORAGE_BUCKET: 'b.appspot.com' }).storageBucket).toBe('b.appspot.com');
  });

  it('does not read the old unprefixed variable names', () => {
    const cfg = configFromEnv({
      FIREBASE_PROJECT_ID: 'old',
      FIREBASE_API_KEY: 'old',
      RESEND_API_KEY: 'old',
      EMAIL_FROM: 'old',
    });
    expect(cfg.projectId).toBeUndefined();
    expect(cfg.apiKey).toBeUndefined();
    expect(cfg.emailSender).toBeUndefined();
  });

  it('leaves emailSender undefined unless both Resend variables are set', () => {
    expect(configFromEnv(ENV).emailSender).toBeUndefined();
    expect(configFromEnv({ ...ENV, GF_RESEND_API_KEY: 're_x' }).emailSender).toBeUndefined();
    expect(configFromEnv({ ...ENV, GF_RESEND_EMAIL_FROM: 'a@b.co' }).emailSender).toBeUndefined();
  });

  it('builds a working Resend sender from FB_RESEND_* variables', async () => {
    const { fetchFn, calls } = createMockFetch(() => ({ id: 'email_1' }));
    vi.stubGlobal('fetch', fetchFn);

    const { emailSender } = configFromEnv({
      ...ENV,
      FB_RESEND_API_KEY: 're_secret',
      FB_RESEND_EMAIL_FROM: 'Acme <no-reply@acme.dev>',
    });
    expect(emailSender).toBeTypeOf('function');

    await emailSender!({ to: 'ada@example.com', subject: 'Hi', text: 'Body' });
    expect(calls[0].url).toBe('https://api.resend.com/emails');
    expect(calls[0].headers.Authorization).toBe('Bearer re_secret');
    expect(calls[0].body).toEqual({
      from: 'Acme <no-reply@acme.dev>',
      to: 'ada@example.com',
      subject: 'Hi',
      text: 'Body',
    });
  });

  it('lets overrides win', () => {
    const sender = async () => true;
    const cfg = configFromEnv(ENV, { usersCollection: 'members', emailSender: sender, projectId: 'other' });
    expect(cfg).toMatchObject({ usersCollection: 'members', projectId: 'other' });
    expect(cfg.emailSender).toBe(sender);
  });

  it('produces a config createFirebaseEdge accepts', () => {
    expect(() => createFirebaseEdge(configFromEnv(ENV))).not.toThrow();
  });
});

describe('resendEmailSender', () => {
  const msg = { to: 'a@b.co', subject: 'S', text: 'T' };

  it('returns true on success', async () => {
    const { fetchFn } = createMockFetch(() => ({ id: '1' }));
    expect(await resendEmailSender({ apiKey: 'k', from: 'f@x.co', fetchFn })(msg)).toBe(true);
  });

  it('returns false and logs on a non-2xx response', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => { });
    const { fetchFn } = createMockFetch(() => apiError('invalid from', 422));
    expect(await resendEmailSender({ apiKey: 'k', from: 'f@x.co', fetchFn })(msg)).toBe(false);
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('propagates network failures so callers can decide (auth.resetUserPassword catches them)', async () => {
    const fetchFn = (async () => {
      throw new TypeError('network down');
    }) as unknown as typeof globalThis.fetch;
    await expect(resendEmailSender({ apiKey: 'k', from: 'f@x.co', fetchFn })(msg)).rejects.toThrow('network down');
  });
});
