import { FirebaseError } from './errors';

const SECURETOKEN_JWKS_URL =
    'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

interface CachedJwks {
    keys: JwksKey[];
    expiresAt: number;
}

interface JwksKey extends JsonWebKey {
    alg?: string;
    kid?: string;
    use?: string;
}

interface IdTokenClaims extends Record<string, unknown> {
    aud: string;
    exp: number;
    iat: number;
    iss: string;
    sub: string;
}

function invalidToken(): FirebaseError {
    return new FirebaseError('INVALID_ID_TOKEN', 'Invalid or expired token', 401);
}

function invalidJwks(): FirebaseError {
    return new FirebaseError('INVALID_JWKS_RESPONSE', 'Google returned invalid signing keys', 502);
}

function decodeBase64Url(value: string): Uint8Array {
    if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw invalidToken();
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    try {
        return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    } catch {
        throw invalidToken();
    }
}

function decodeJsonSegment(value: string): Record<string, unknown> {
    try {
        const parsed: unknown = JSON.parse(
            new TextDecoder('utf-8', { fatal: true }).decode(decodeBase64Url(value))
        );
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw invalidToken();
        return parsed as Record<string, unknown>;
    } catch (error) {
        if (error instanceof FirebaseError) throw error;
        throw invalidToken();
    }
}

function cacheLifetime(response: Response): number {
    const directives = (response.headers.get('cache-control') ?? '')
        .split(',')
        .map((directive) => directive.trim());
    if (directives.some((directive) => /^(no-store|no-cache)$/i.test(directive))) return 0;

    const maxAge = directives
        .map((directive) => directive.match(/^max-age\s*=\s*"?(\d+)"?$/i))
        .find((match) => match)?.[1];
    if (maxAge === undefined) return 0;

    const age = Number.parseInt(response.headers.get('age') ?? '0', 10);
    return Math.max(
        0,
        Number(maxAge) * 1000 - (Number.isFinite(age) ? Math.max(0, age) * 1000 : 0)
    );
}

/** Creates a per-client verifier that caches Google's signing keys and shares in-flight fetches. */
export function createIdTokenVerifier(projectId: string, fetchFn: typeof fetch) {
    let cachedJwks: CachedJwks | null = null;
    let jwksRequest: Promise<CachedJwks> | null = null;
    const importedKeys = new Map<string, Promise<CryptoKey>>();

    async function fetchJwks(): Promise<CachedJwks> {
        const response = await fetchFn(SECURETOKEN_JWKS_URL);
        if (!response.ok) {
            throw new FirebaseError(
                'JWKS_FETCH_FAILED',
                `Failed to fetch Google signing keys (${response.status})`,
                502
            );
        }

        let body: unknown;
        try {
            body = await response.json();
        } catch {
            throw invalidJwks();
        }

        if (
            !body ||
            typeof body !== 'object' ||
            !('keys' in body) ||
            !Array.isArray(body.keys) ||
            !body.keys.every((key) => key && typeof key === 'object' && !Array.isArray(key))
        ) {
            throw invalidJwks();
        }

        const keys = body.keys as JwksKey[];
        if (keys.length === 0) throw invalidJwks();

        const result = {
            keys,
            expiresAt: Date.now() + cacheLifetime(response),
        };
        cachedJwks = result;
        importedKeys.clear();
        return result;
    }

    function getJwks(): Promise<CachedJwks> {
        if (cachedJwks && cachedJwks.expiresAt > Date.now()) {
            return Promise.resolve(cachedJwks);
        }
        if (!jwksRequest) {
            jwksRequest = fetchJwks().finally(() => {
                jwksRequest = null;
            });
        }
        return jwksRequest;
    }

    async function getVerificationKey(kid: string): Promise<CryptoKey | null> {
        const jwks = await getJwks();
        const jwk = jwks.keys.find(
            (key) =>
                key.kid === kid &&
                key.kty === 'RSA' &&
                (key.alg === undefined || key.alg === 'RS256') &&
                (key.use === undefined || key.use === 'sig') &&
                typeof key.n === 'string' &&
                typeof key.e === 'string'
        );
        if (!jwk) return null;

        let imported = importedKeys.get(kid);
        if (!imported) {
            imported = crypto.subtle
                .importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
                    'verify',
                ])
                .catch(() => {
                    importedKeys.delete(kid);
                    throw invalidJwks();
                });
            importedKeys.set(kid, imported);
        }
        return imported;
    }

    return async function verifyIdToken(
        idToken: string
    ): Promise<{ uid: string; [key: string]: any }> {
        const segments = idToken.split('.');
        if (segments.length !== 3) throw invalidToken();

        const [encodedHeader, encodedPayload, encodedSignature] = segments;
        const header = decodeJsonSegment(encodedHeader);
        const claims = decodeJsonSegment(encodedPayload) as IdTokenClaims;
        if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid) {
            throw invalidToken();
        }

        const now = Math.floor(Date.now() / 1000);
        if (
            claims.iss !== `https://securetoken.google.com/${projectId}` ||
            claims.aud !== projectId ||
            typeof claims.exp !== 'number' ||
            !Number.isFinite(claims.exp) ||
            claims.exp <= now ||
            typeof claims.iat !== 'number' ||
            !Number.isFinite(claims.iat) ||
            claims.iat < 0 ||
            claims.iat > now ||
            typeof claims.sub !== 'string' ||
            claims.sub.length === 0
        ) {
            throw invalidToken();
        }

        const decodedSignature = decodeBase64Url(encodedSignature);
        const key = await getVerificationKey(header.kid);
        if (!key) throw invalidToken();

        const signature = new ArrayBuffer(decodedSignature.byteLength);
        new Uint8Array(signature).set(decodedSignature);
        let validSignature: boolean;
        try {
            validSignature = await crypto.subtle.verify(
                'RSASSA-PKCS1-v1_5',
                key,
                signature,
                new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
            );
        } catch {
            throw invalidToken();
        }
        if (!validSignature) throw invalidToken();

        return {
            ...claims,
            uid: claims.sub,
            email: claims.email,
            emailVerified: claims.email_verified === true,
        };
    };
}
