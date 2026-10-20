import { createFirebaseEdge, generateDocId } from '../dist/index.js';

function assert(condition, message) {
    if (!condition) throw new Error(message);
}

function decodeBase64Url(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

function decodeJwtPart(value) {
    return JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
}

function toPem(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return `-----BEGIN PRIVATE KEY-----\n${btoa(binary)}\n-----END PRIVATE KEY-----`;
}

const { privateKey, publicKey } = await crypto.subtle.generateKey(
    {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
);
const privateKeyPem = toPem(await crypto.subtle.exportKey('pkcs8', privateKey));

let tokenRequests = 0;
let queryRequests = 0;
const fetchFn = async (input, init = {}) => {
    const url = String(input);

    if (url === 'https://oauth2.googleapis.com/token') {
        tokenRequests++;
        const form = new URLSearchParams(String(init.body));
        assert(
            form.get('grant_type') === 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'OAuth request did not use the JWT bearer grant'
        );

        const assertion = form.get('assertion');
        assert(assertion, 'OAuth request did not contain a signed assertion');
        const [header, payload, signature] = assertion.split('.');
        assert(decodeJwtPart(header).alg === 'RS256', 'JWT did not use RS256');
        assert(
            decodeJwtPart(payload).iss === 'runtime-smoke@example.test',
            'JWT issuer did not match the service account'
        );
        assert(
            await crypto.subtle.verify(
                'RSASSA-PKCS1-v1_5',
                publicKey,
                decodeBase64Url(signature),
                new TextEncoder().encode(`${header}.${payload}`)
            ),
            'JWT signature did not verify with Web Crypto'
        );

        return Response.json({
            access_token: 'runtime-smoke-token',
            expires_in: 3600,
        });
    }

    if (url.endsWith(':runQuery')) {
        const { structureQuery } = JSON.parse(String(init.body));
        assert(structureQuery.limit === 1, 'Firestore query did not preserve the page size');
        assert(
            structureQuery.orderBy?.[0]?.field?.fieldPath === '__name__',
            'Firestore pagination did not use document-name ordering'
        );
        if (queryRequests === 0) {
            assert(!structureQuery.startAt, 'First page unexpectedly included a cursor');
        } else {
            assert(
                structureQuery.startAt?.values?.[0]?.referenceValue?.endsWith('/items/a'),
                'Next page did not use the previous document as its cursor'
            );
        }

        queryRequests++;
        const id = queryRequests === 1 ? 'a' : 'b';
        return Response.json([
            {
                document: {
                    name: `projects/runtime-smoke/databases/(default)/documents/items/${id}`,
                    fields: { score: { integerValue: String(queryRequests) } },
                },
            },
        ]);
    }

    throw new Error(`Unexpected request: ${url}`);
};

const firebase = createFirebaseEdge({
    projectId: 'runtime-smoke',
    clientEmail: 'runtime-smoke@example.test',
    privateKeyId: 'runtime-smoke-key',
    privateKey: privateKeyPem,
    apiKey: 'runtime-smoke-api-key',
    fetchFn,
});

const firstPage = await firebase.firestore.list('items', { limit: 1 });
assert(firstPage.documents[0]?.id === 'a', 'First page document was not decoded');
assert(firstPage.documents[0]?.score === 1, 'First page field was not decoded');
assert(firstPage.nextPageToken, 'First page did not return a continuation token');

const secondPage = await firebase.firestore.list('items', {
    limit: 1,
    pageToken: firstPage.nextPageToken,
});
assert(secondPage.documents[0]?.id === 'b', 'Second page document was not decoded');
assert(tokenRequests === 1, 'Access token was not reused between Firestore requests');
assert(queryRequests === 2, 'Expected exactly two Firestore page requests');
assert(/^[A-Za-z0-9]{20}$/.test(generateDocId()), 'Document ID generation failed');

console.log('Runtime smoke test passed');
