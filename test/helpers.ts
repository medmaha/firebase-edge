// @ts-nocheck
import { generateKeyPairSync } from 'node:crypto';
import { vi } from 'vitest';
import type { Context } from '../src/types';

// ---- constants ------------------------------------------------------------
export const PROJECT_ID = 'test-project';
export const DATABASE_NAME = 'test-db';
export const API_KEY = 'test-api-key';
export const BUCKET = 'test-project.firebasestorage.app';
export const CLIENT_EMAIL = 'svc@test-project.iam.gserviceaccount.com';
export const TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const IDT_PUBLIC = 'https://identitytoolkit.googleapis.com/v1';
export const IDT_ADMIN = `${IDT_PUBLIC}/projects/${PROJECT_ID}`;
export const FS_DOCS = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(${DATABASE_NAME})/documents`;
export const DOC_NAME = (path: string) =>
  `projects/${PROJECT_ID}/databases/(${DATABASE_NAME})/documents/${path}`;

// ---- real RSA key pair so JWT signing actually runs -------------------------
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
export const PRIVATE_KEY_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
export const PUBLIC_KEY_PEM = publicKey.export({ type: 'spki', format: 'pem' }) as string;

// ---- mock fetch -------------------------------------------------------------
export interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: any; // parsed JSON when possible, raw string otherwise
}
export type Reply = Response | Record<string, unknown> | unknown[] | undefined;
export type Handler = (call: Call) => Reply | Promise<Reply>;

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Shape of a Google API error response. */
export function apiError(message: string, status = 400, extra: Record<string, unknown> = {}) {
  return jsonResponse({ error: { message, ...extra } }, status);
}

function parseBody(raw: unknown) {
  if (typeof raw !== 'string') return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

/**
 * Records every call. The handler may return undefined to fall through:
 * the OAuth token endpoint then gets a default response (distinct token per fetch),
 * anything else gets a 500 "UNHANDLED" so missing routes fail loudly.
 */
export function createMockFetch(handler: Handler = () => undefined) {
  const calls: Call[] = [];
  let tokenCount = 0;

  const fn = vi.fn(async (input: any, init: RequestInit = {}) => {
    const call: Call = {
      url: String(input),
      method: init.method ?? 'GET',
      headers: { ...((init.headers as Record<string, string>) ?? {}) },
      body: parseBody(init.body),
    };
    calls.push(call);

    let reply = await handler(call);
    if (reply === undefined && call.url === TOKEN_URL) {
      tokenCount++;
      reply = { access_token: `test-token-${tokenCount}`, expires_in: 3600 };
    }
    if (reply === undefined) {
      return jsonResponse({ error: { message: `UNHANDLED ${call.method} ${call.body} ${call.url}` } }, 500);
    }
    return reply instanceof Response ? reply : jsonResponse(reply);
  });

  return { fetchFn: fn as unknown as typeof fetch, fn, calls };
}

/**
 * Route table helper. A pattern is "METHOD url" and matches exactly
 * (or the same url followed by a query string).
 */
export function routes(table: Array<[string, (call: Call) => Reply]>): Handler {
  return (call) => {
    const key = `${call.method} ${call.url}`;
    for (const [pattern, respond] of table) {
      if (key === pattern || key.startsWith(pattern + '?')) return respond(call);
    }
    return undefined;
  };
}

/** Context with a stubbed access-token provider (skips the OAuth flow). */
export function makeCtx(handler: Handler = () => undefined, overrides: Partial<Context> = {}) {
  const mock = createMockFetch(handler);
  const ctx: Context = {
    projectId: PROJECT_ID,
    apiKey: API_KEY,
    databaseName: DATABASE_NAME,
    usersCollection: 'users',
    storageBucket: BUCKET,
    clientEmail: CLIENT_EMAIL,
    fetchFn: mock.fetchFn,
    getAccessToken: async () => 'test-token',
    sign: async (data) => new TextEncoder().encode(`sig:${data.length}`).buffer,
    ...overrides,
  };
  return { ctx, ...mock };
}

// ---- assertions helpers -----------------------------------------------------
export const callsTo = (calls: Call[], method: string, urlPrefix: string) =>
  calls.filter((c) => c.method === method && c.url.startsWith(urlPrefix));

/** First write of every Firestore :commit call, in order. */
export const commitWrites = (calls: Call[]) =>
  callsTo(calls, 'POST', `${FS_DOCS}:commit`).map((c) => c.body.writes[0]);

export function b64urlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
export const b64urlToJson = (s: string) =>
  JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
