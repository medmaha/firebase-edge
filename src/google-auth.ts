import { base64UrlEncode, pemToDer } from './utils';

const OAUTH2_TOKEN_URL = 'https://oauth2.googleapis.com/token';

export interface ServiceAccount {
    projectId: string;
    clientEmail: string;
    privateKey: string;
    privateKeyId: string;
}

/** Lazily imports (and caches) the service-account key for RSASSA-PKCS1-v1_5 / SHA-256 signing. */
function createKeyLoader(sa: ServiceAccount): () => Promise<CryptoKey> {
    let signingKey: Promise<CryptoKey> | null = null;
    return () => {
        if (!signingKey) {
            signingKey = crypto.subtle
                .importKey(
                    'pkcs8',
                    pemToDer(sa.privateKey),
                    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
                    false,
                    ['sign']
                )
                .catch((err) => {
                    signingKey = null;
                    throw err;
                });
        }
        return signingKey;
    };
}

/** Signs arbitrary bytes with the service-account key (RSA-SHA256). Used for Storage signed URLs. */
export function createSigner(sa: ServiceAccount): (data: Uint8Array) => Promise<ArrayBuffer> {
    const getSigningKey = createKeyLoader(sa);
    return async (data) =>
        crypto.subtle.sign('RSASSA-PKCS1-v1_5', await getSigningKey(), data as BufferSource);
}

/** Per-client OAuth2 token provider with caching and in-flight de-duplication. */
export function createTokenProvider(sa: ServiceAccount, fetchFn: typeof fetch) {
    const cache = new Map<string, { token: string; expiresAt: number }>();
    const inflight = new Map<string, Promise<string>>();
    const getSigningKey = createKeyLoader(sa);

    async function signJwt(scope: string): Promise<string> {
        const now = Math.floor(Date.now() / 1000);
        const enc = new TextEncoder();
        const header = base64UrlEncode(
            enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: sa.privateKeyId }))
        );
        const payload = base64UrlEncode(
            enc.encode(
                JSON.stringify({
                    iss: sa.clientEmail,
                    scope,
                    aud: OAUTH2_TOKEN_URL,
                    exp: now + 3600,
                    iat: now,
                })
            )
        );
        const unsigned = `${header}.${payload}`;
        const signature = await crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            await getSigningKey(),
            enc.encode(unsigned)
        );
        return `${unsigned}.${base64UrlEncode(signature)}`;
    }

    async function fetchToken(scope: string): Promise<string> {
        const res = await fetchFn(OAUTH2_TOKEN_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                assertion: await signJwt(scope),
            }).toString(),
        });
        const data: any = await res.json().catch(() => ({}));
        if (!res.ok || !data.access_token) {
            throw new Error(`Failed to get access token: ${JSON.stringify(data)}`);
        }
        cache.set(scope, {
            token: data.access_token,
            expiresAt: Date.now() + ((data.expires_in ?? 3600) - 60) * 1000,
        });
        return data.access_token;
    }

    /**
     * Retrieves a valid OAuth 2.0 access token for the provided scope.
     * Reuses cached tokens and de-dupes in-flight requests by scope.
     * @param scope - The OAuth scope requested from Google.
     * @returns A promise that resolves to the access token.
     */
    function getAccessToken(scope: string): Promise<string> {
        const cached = cache.get(scope);
        if (cached && cached.expiresAt > Date.now()) return Promise.resolve(cached.token);

        let pending = inflight.get(scope);
        if (!pending) {
            pending = fetchToken(scope).finally(() => inflight.delete(scope));
            inflight.set(scope, pending);
        }
        return pending;
    }

    return getAccessToken;
}
