import { createAuth } from './auth';
import { createFirestore } from './firestore';
import { createSigner, createTokenProvider } from './google-auth';
import { createStorage } from './storage';
import { resendEmailSender } from './email';
import type { Context, FirebaseConfig } from './types';

export { FirebaseError } from './errors';

/**
 * Creates a client. Construct once per isolate/process and reuse it:
 * token and key caches live inside the client.
 *
 * @param config - The Firebase configuration object containing credentials and options.
 * @returns An object containing initialized auth, firestore, storage, and token provider utilities.
 * @throws {Error} If any required configuration values are missing.
 */
export function createFirebaseEdge(config: FirebaseConfig) {
    const required = ['projectId', 'clientEmail', 'privateKey', 'privateKeyId', 'apiKey'] as const;
    const missing = required.filter((k) => !config[k]);
    if (missing.length) {
        throw new Error(`createFirebaseEdge: missing config values: ${missing.join(', ')}`);
    }

    // Wrapped so an unbound global fetch never throws "Illegal invocation" on Workers
    const fetchFn: typeof fetch =
        config.fetchFn ?? ((...args: Parameters<typeof fetch>) => fetch(...args));

    const serviceAccount = {
        projectId: config.projectId,
        clientEmail: config.clientEmail,
        privateKeyId: config.privateKeyId,
        privateKey: config.privateKey.replace(/^"|"$/g, '').replace(/\\n/g, '\n'),
    };
    const getAccessToken = createTokenProvider(serviceAccount, fetchFn);

    const ctx: Context = {
        projectId: config.projectId,
        apiKey: config.apiKey,
        databaseName: config.databaseName ?? 'default',
        usersCollection: config.usersCollection ?? 'users',
        minAuthPasswordLength: config.minAuthPasswordLength,
        allowFirestoreAuthCollection: config.allowFirestoreAuthCollection,
        storageBucket: config.storageBucket ?? `${config.projectId}.firebasestorage.app`,
        clientEmail: config.clientEmail,
        fetchFn: fetchFn,
        getAccessToken,
        sign: createSigner(serviceAccount),
    };

    const firestore = createFirestore(ctx);
    const auth = createAuth(ctx, firestore, config.emailSender);
    const storage = createStorage(ctx);

    return { auth, firestore, storage, getAccessToken };
}

export type FirebaseClient = ReturnType<typeof createFirebaseEdge>;

/**
 * Build a config from an env-like object. Works with Workers' `env`,
 * `process.env`, `Deno.env.toObject()`, etc.
 * Reads FB_PROJECT_ID, FB_CLIENT_EMAIL, FB_PRIVATE_KEY_ID,
 * FB_PRIVATE_KEY, FB_API_KEY and optionally FB_STORAGE_BUCKET, FB_RESEND_API_KEY + FB_RESEND_EMAIL_FROM.
 *
 * @param env - The environment variables record mapping string keys to values.
 * @param overrides - Optional configuration properties to override values from the environment.
 * @returns A fully constructed FirebaseConfig object.
 */
export function configFromEnv(
    env: Record<string, string | undefined>,
    overrides: Partial<FirebaseConfig> = {}
): FirebaseConfig {
    return {
        projectId: env.FB_PROJECT_ID!,
        clientEmail: env.FB_CLIENT_EMAIL!,
        privateKeyId: env.FB_PRIVATE_KEY_ID!,
        privateKey: env.FB_PRIVATE_KEY!,
        apiKey: env.FB_API_KEY!,
        storageBucket: env.FB_STORAGE_BUCKET || undefined,
        emailSender:
            env.FB_RESEND_API_KEY && env.FB_RESEND_EMAIL_FROM
                ? resendEmailSender({
                      apiKey: env.FB_RESEND_API_KEY,
                      from: env.FB_RESEND_EMAIL_FROM,
                  })
                : undefined,
        ...overrides,
    };
}

export type { AuthApi, CreateUserPayload, VerifyIdTokenOptions } from './types/auth';
export type { FirestoreApi, FirestoreListQuery } from './types/firestore';
export type {
    StorageApi,
    StorageData,
    StorageListQuery,
    StorageObject,
    SignedUrlOptions,
    UpdateMetadataOptions,
    UploadOptions,
} from './types/storage';
export type { FirebaseConfig, EmailSender, EmailMessage } from './types';

export { generateDocId } from './utils';
export { resendEmailSender } from './email';
