import { noopLogger, type Logger } from './logger';
import { base64UrlEncode, pemToDer } from './utils';

const OAUTH2_TOKEN_URL = 'https://oauth2.googleapis.com/token';

export interface ServiceAccount {
    projectId: string;
    clientEmail: string;
    privateKey: string;
    privateKeyId: string;
}

/** Lazily imports (and caches) the service-account key for RSASSA-PKCS1-v1_5 / SHA-256 signing. */
function createKeyLoader(sa: ServiceAccount, log: Logger): () => Promise<CryptoKey> {
    let signingKey: Promise<CryptoKey> | null = null;
    return () => {
        if (!signingKey) {
            log.debug('importing service-account signing key');
            // Promise.resolve().then(...) so a malformed PEM (pemToDer throws synchronously)
            // is logged and cleared like any other import failure.
            signingKey = Promise.resolve()
                .then(() =>
                    crypto.subtle.importKey(
                        'pkcs8',
                        pemToDer(sa.privateKey),
                        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
                        false,
                        ['sign']
                    )
                )
                .catch((err) => {
                    signingKey = null;
                    log.error(
                        'failed to import the service-account private key (check FB_PRIVATE_KEY formatting)',
                        undefined,
                        err
                    );
                    throw err;
                });
        }
        return signingKey;
    };
}

/** Signs arbitrary bytes with the service-account key (RSA-SHA256). Used for Storage signed URLs. */
export function createSigner(
    sa: ServiceAccount,
    log: Logger = noopLogger
): (data: Uint8Array) => Promise<ArrayBuffer> {
    const getSigningKey = createKeyLoader(sa, log.child('signer'));
    return async (data) =>
        crypto.subtle.sign('RSASSA-PKCS1-v1_5', await getSigningKey(), data as BufferSource);
}

/** Per-client OAuth2 token provider with caching and in-flight de-duplication. */
export function createTokenProvider(
    sa: ServiceAccount,
    fetchFn: typeof fetch,
    logger: Logger = noopLogger
) {
    const log = logger.child('token');
    const _cache = new Map<string, { token: string; expiresAt: number }>();
    const _inflight = new Map<string, Promise<string>>();

    const getSigningKey = createKeyLoader(sa, log);

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
        _cache.set(scope, {
            token: data.access_token,
            expiresAt: Date.now() + ((data.expires_in ?? 3600) - 60) * 1000,
        });
        log.info('access token refreshed', { scope, expiresInSec: data.expires_in ?? 3600 });
        return data.access_token;
    }

    /**
     * Retrieves a valid OAuth 2.0 access token for the provided scope.
     * Reuses cached tokens and de-dupes in-flight requests by scope.
     * @param scope - The OAuth scope requested from Google.
     * @returns A promise that resolves to the access token.
     */
    function getAccessToken(scope: string): Promise<string> {
        const cached = _cache.get(scope);
        if (cached && cached.expiresAt > Date.now()) {
            log.debug('token cache hit', () => ({
                scope,
                expiresInSec: Math.round((cached.expiresAt - Date.now()) / 1000),
            }));
            return Promise.resolve(cached.token);
        }

        let pending = _inflight.get(scope);
        if (pending) {
            log.debug('joining in-flight token request', { scope });
        } else {
            log.debug(cached ? 'token expired, refreshing' : 'token cache miss', { scope });
            pending = fetchToken(scope)
                .catch((err) => {
                    log.error('access token request failed', { scope }, err);
                    throw err;
                })
                .finally(() => _inflight.delete(scope));
            _inflight.set(scope, pending);
        }
        return pending;
    }

    return getAccessToken;
}
