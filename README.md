# firebase-edge

Firebase Authentication, Firestore and Cloud Storage helpers that use Google's REST APIs. The package has no runtime dependencies and uses standard `fetch` and Web Crypto APIs.

It is intended for server-side use in Node.js 20+, Deno, Bun, Cloudflare Workers, and Vercel Edge. It uses service-account credentials with administrative access: **never expose your private key to a browser or commit it to your repository.**

## Install

```sh
npm install firebase-edge
```

## Quick start

Set the required environment variables:

```text
FB_PROJECT_ID=your-firebase-project-id
FB_CLIENT_EMAIL=firebase-adminsdk@example.iam.gserviceaccount.com
FB_PRIVATE_KEY_ID=your-private-key-id
FB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
FB_API_KEY=your-firebase-web-api-key
FB_STORAGE_BUCKET=your-project.firebasestorage.app   # optional
```

Then create and reuse a client:

```ts
import { configFromEnv, createFirebaseEdge, generateDocId } from 'firebase-edge';

const firebase = createFirebaseEdge(configFromEnv(process.env));

const { uid } = await firebase.auth.createUser({
    email: 'ada@example.com',
    password: 'correct-horse-battery',
    displayName: 'John Doe',
    claims: { role: 'admin' },
});

const tokenInfo = await firebase.auth.verifyIdToken(idToken);
await firebase.firestore.set('orders', generateDocId(), { total: 42.5 });
```

Create one client per process or isolate and reuse it. The client caches access tokens between requests.

## Cloudflare Workers

Keep the client in the module scope so it is reused within an isolate. Store credentials as Worker secrets, not in source code:

```ts
import { createFirebaseEdge, type FirebaseClient } from 'firebase-edge';

interface Env {
    FB_PROJECT_ID: string;
    FB_CLIENT_EMAIL: string;
    FB_PRIVATE_KEY_ID: string;
    FB_PRIVATE_KEY: string;
    FB_API_KEY: string;
}

let firebase: FirebaseClient | undefined;

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        firebase ??= createFirebaseEdge({
            projectId: env.FB_PROJECT_ID,
            clientEmail: env.FB_CLIENT_EMAIL,
            privateKeyId: env.FB_PRIVATE_KEY_ID,
            privateKey: env.FB_PRIVATE_KEY,
            apiKey: env.FB_API_KEY,
        });

        return new Response('Firebase client is ready');
    },
};
```

## Configuration

`createFirebaseEdge()` requires the following values:

| Option         | Description                                                                              |
| -------------- | ---------------------------------------------------------------------------------------- |
| `projectId`    | Firebase project ID.                                                                     |
| `clientEmail`  | Service-account email address.                                                           |
| `privateKeyId` | Service-account private key ID.                                                          |
| `privateKey`   | Service-account PEM private key. Escaped `\n` sequences and wrapping quotes are handled. |
| `apiKey`       | Firebase Web API key, used for public Identity Toolkit endpoints.                        |

Optional `FirebaseConfig` values:

| Option                         | Default                           | Description                                                                                                     |
| ------------------------------ | --------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `databaseName`                 | `default`                         | Firestore database name.                                                                                        |
| `usersCollection`              | `users`                           | Collection used to mirror Auth user profile data.                                                               |
| `allowFirestoreAuthCollection` | `true`                            | Set to `false` to disable automatic Auth profile writes to Firestore.                                           |
| `minAuthPasswordLength`        | `6`                               | Minimum password length checked by password operations.                                                         |
| `storageBucket`                | `<projectId>.firebasestorage.app` | Cloud Storage bucket used by `storage`. Projects created before Oct 2024 usually use `<projectId>.appspot.com`. |
| `emailSender`                  | —                                 | Async callback used to notify users after an admin password reset.                                              |
| `fetchFn`                      | global `fetch`                    | Optional custom fetch implementation, useful for tests or proxies.                                              |

`configFromEnv(env, overrides?)` reads `FB_PROJECT_ID`, `FB_CLIENT_EMAIL`, `FB_PRIVATE_KEY_ID`, `FB_PRIVATE_KEY`, and `FB_API_KEY`, plus the optional `FB_STORAGE_BUCKET`. It also configures the built-in Resend sender when both `FB_RESEND_API_KEY` and `FB_RESEND_EMAIL_FROM` are set. Pass optional client settings in `overrides`.

To use Resend directly, call `resendEmailSender({ apiKey, from })` and pass the result as `emailSender`. A custom sender can implement the exported `EmailSender` type.

## Authentication

The `auth` client provides:

| Method                                       | Purpose                                                                                                                      |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `createUser(options)`                        | Creates an Auth user and, by default, a matching Firestore profile. Requires a password and either an email or phone number. |
| `verifyIdToken(token)`                       | Looks up and verifies the ID token with Firebase, returning the UID, email, verification state, and custom claims.           |
| `setCustomUserClaims(uid, claims)`           | Sets the user's custom claims in Auth. This replaces the custom-claims object.                                               |
| `updateUser(uid, fields)`                    | Updates supported Auth fields and the Firestore profile. Passwords are not copied into Firestore.                            |
| `disableUser(uid, disabled?)`                | Sets the disabled state, or toggles it when `disabled` is omitted.                                                           |
| `deleteUserPermanent(uid)`                   | Permanently deletes the Auth user and its mirrored Firestore profile.                                                        |
| `resetUserPassword(uid, newPassword)`        | Changes the password, revokes existing sessions, and attempts to notify the user. Returns `{ uid, emailSent }`.              |
| `requestPasswordReset(email, continueUrl?)`  | Requests a Firebase password-reset email without revealing whether the address is registered.                                |
| `verifyPasswordResetCode(oobCode)`           | Checks a password-reset code and returns the associated email.                                                               |
| `confirmPasswordReset(oobCode, newPassword)` | Completes a password reset with the code and new password.                                                                   |

Pass custom claims when creating a user or set them later:

```ts
await firebase.auth.setCustomUserClaims(uid, { role: 'admin' });
```

Claims are stored on the Auth user; they are not automatically copied into the Firestore profile. Custom claims are limited to 1,000 bytes.

`verifyIdToken()` makes a network request to Firebase for each verification. This lets it detect disabled users and return current claims, but adds request latency and uses the Identity Toolkit API.

## Firestore

The `firestore` client provides `set`, `update`, `get`, `list`, and `delete`.

```ts
await firebase.firestore.set('orders', 'order-123', { status: 'pending' });
await firebase.firestore.set('orders', 'order-123', { status: 'paid' }, { merge: true });

await firebase.firestore.update(
    'orders',
    'order-123',
    { status: 'paid' },
    { increments: { attempts: 1 } }
);

const order = await firebase.firestore.get<{ status: string }>('orders', 'order-123');
```

`set()` replaces the document unless `{ merge: true }` is provided. `update()` writes only the supplied fields and can atomically increment numeric fields. `get()` returns decoded document data or `null` if the document does not exist. Deleting a missing document is a no-op.

### Query and paginate

`list()` returns `{ documents, nextPageToken }`. It accepts one field filter, optional ordering, and a page size (100 by default, capped at 500):

```ts
const firstPage = await firebase.firestore.list('orders', {
    field: 'status',
    op: 'EQUAL',
    value: 'paid',
    orderBy: 'createdAt',
    direction: 'DESCENDING',
    limit: 100,
});

if (firstPage.nextPageToken) {
    const nextPage = await firebase.firestore.list('orders', {
        field: 'status',
        op: 'EQUAL',
        value: 'paid',
        orderBy: 'createdAt',
        direction: 'DESCENDING',
        limit: 100,
        pageToken: firstPage.nextPageToken,
    });
}
```

Each document in `documents` contains its decoded fields and an `id`. Page tokens are opaque and are only valid for the same collection and query.

## Firestore user profiles

When `allowFirestoreAuthCollection` is enabled (the default), Auth operations mirror profile and password-reset metadata to `usersCollection`. New profiles include fields such as `email`, `displayName`, `phoneNumber`, `disabled`, `disabledAt`, `passwordResetCount`, `createdAt`, and `updatedAt`. Password-reset operations may add `passwordResetAt`, `passwordResetLinkSentAt`, `passwordResetLinkVerifiedAt`, and `passwordResetConfirmedAt`.

The timestamps in these profile fields are epoch milliseconds. Custom claims are stored in Firebase Auth, not in the profile document.

## Cloud Storage

`firebase.storage` talks to the Cloud Storage JSON API for your Firebase bucket using the service account. **This is administrative access: Firebase Security Rules do not apply**, so enforce your own authorization before calling it with user-supplied paths. The service account needs a role such as Storage Object Admin on the bucket.

| Method                                          | Purpose                                                                                                                                                   |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `upload(path, data, options?)`                  | Uploads a `string`, `Uint8Array`/`ArrayBuffer` or `Blob` and returns the object's metadata. Uses a multipart request, or a resumable session above 8 MiB. |
| `download(path)`                                | Returns the bytes, or `null` if the object does not exist.                                                                                                |
| `downloadStream(path)`                          | Same, but as a `ReadableStream`, e.g. to proxy a file from a Worker.                                                                                      |
| `getMetadata(path)`                             | Returns the object's metadata, or `null` if it does not exist.                                                                                            |
| `updateMetadata(path, options)`                 | Updates content type, cache control, disposition or custom metadata (a `null` value removes a key).                                                       |
| `list({ prefix, delimiter, limit, pageToken })` | Returns `{ objects, prefixes, nextPageToken }`. `limit` defaults to 100 (max 1000).                                                                       |
| `delete(path)`                                  | Deletes the object. Deleting a missing object is a no-op.                                                                                                 |
| `getDownloadUrl(path)`                          | Returns a Firebase-style tokenized URL (like `getDownloadURL()` in the client SDK), creating a token if needed.                                           |
| `signedUrl(path, options?)`                     | Returns a V4 signed URL for `GET`, `PUT`, `DELETE` or `HEAD`. Signed locally, no network request.                                                         |

```ts
const { storage } = firebase;

await storage.upload('avatars/ada.png', pngBytes, {
    contentType: 'image/png',
    cacheControl: 'public, max-age=86400',
    metadata: { owner: uid },
    ifGenerationMatch: 0, // fail instead of overwriting
});

const bytes = await storage.download('avatars/ada.png'); // Uint8Array | null
const { objects, prefixes } = await storage.list({ prefix: 'avatars/', delimiter: '/' });

// Let a browser upload directly, or download with a time limit
const uploadUrl = await storage.signedUrl('avatars/ada.png', {
    method: 'PUT',
    contentType: 'image/png', // the client must send this exact Content-Type
    expiresIn: 600,
});
const downloadUrl = await storage.signedUrl('avatars/ada.png', {
    responseDisposition: 'attachment; filename="ada.png"',
});

// Long-lived public-by-link URL, same as the client SDK's getDownloadURL()
const permanentUrl = await storage.getDownloadUrl('avatars/ada.png');
```

Object names follow Cloud Storage rules: 1 to 1,024 bytes, no leading `/`, and no `.` or `..` segments. Signed URLs last at most 7 days. Failures are thrown as `FirebaseError` with the Cloud Storage error reason (for example `conditionNotMet`) as `code`.

## Errors

API errors are thrown as `FirebaseError`, which exposes a Firebase-style `code` and, when available, an HTTP `status`:

```ts
import { FirebaseError } from 'firebase-edge';

try {
    await firebase.auth.verifyIdToken(token);
} catch (error) {
    if (error instanceof FirebaseError) {
        console.error(error.code, error.status);
    }
    throw error;
}
```

## Runtime support

The package requires Node.js 20 or later and is built on standard `fetch` and Web Crypto APIs.

| Runtime                            | Notes                                                                                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Node.js                            | Requires Node.js 20 or later. CI is configured for Node 20, 22, and 24.                                                |
| Deno and Bun                       | CI has portable-runtime smoke-test jobs.                                                                               |
| Cloudflare Workers (workerd)       | Tested in CI using Miniflare and the shared runtime smoke test.                                                       |
| Vercel Edge                        | Designed for this Web API-based runtime; CI does not currently run a Vercel Edge isolate test.                       |

Run the Node.js and Cloudflare Workers smoke tests locally with:

```sh
pnpm run test:runtime
pnpm run test:workers
```

## Scope and limitations

This is a small Auth, Firestore and Cloud Storage REST client, not a complete replacement for `firebase-admin` sdk. It does not provide Cloud Messaging, session cookies, or multi-tenancy support. Storage uploads are buffered in memory (no streaming uploads), and object copy/compose are not included. `firestore.list()` runs a single query and returns at most 500 documents per page; use its page token to fetch more.

Because the service-account key grants administrative access, keep it in your deployment platform's secret manager and restrict access to it. Never ship it to browsers or commit it to the repository.
