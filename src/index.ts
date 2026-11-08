import { createAuth } from './auth';
import { createFirestore } from './firestore';
import { createSigner, createTokenProvider } from './google-auth';
import { createStorage } from './storage';
import { resendEmailSender } from './email';
import { instrumentApi, withFetchLogging } from './instrument';
import { createLogger, isLogLevel } from './logger';
import type { Context, FirebaseConfig } from './types';
import type { AuthApi } from './types/auth';
import type { FirestoreApi } from './types/firestore';
import type { StorageApi } from './types/storage';

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

    const log = createLogger(config.logger);

    // Wrapped so an unbound global fetch never throws "Illegal invocation" on Workers.
    // Logging (when enabled) wraps it once here, so every outbound request is covered.
    const fetchFn: typeof fetch = withFetchLogging(
        config.fetchFn ?? ((...args: Parameters<typeof fetch>) => fetch(...args)),
        log
    );

    const serviceAccount = {
        projectId: config.projectId,
        clientEmail: config.clientEmail,
        privateKeyId: config.privateKeyId,
        privateKey: config.privateKey.replace(/^"|"$/g, '').replace(/\\n/g, '\n'),
    };
    log.debug('service account normalised', {
        privateKeyLooksLikePem: /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(serviceAccount.privateKey),
        privateKeyLines: serviceAccount.privateKey.split('\n').length,
    });
    const getAccessToken = createTokenProvider(serviceAccount, fetchFn, log);

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
        log,
        sign: createSigner(serviceAccount, log),
    };

    // Instrumentation is a no-op passthrough unless logging is enabled.
    // auth receives the instrumented firestore so nested calls show up in traces.
    const firestore = instrumentApi<FirestoreApi>('firestore', createFirestore(ctx), log, {
        set: ([collection, docId]) => ({ collection, docId }),
        update: ([collection, docId]) => ({ collection, docId }),
        get: ([collection, docId]) => ({ collection, docId }),
        delete: ([collection, docId]) => ({ collection, docId }),
        list: ([collection]) => ({ collection }),
    }, {
        set: ['collection', 'docId', 'data', 'options'],
        update: ['collection', 'docId', 'data', 'options'],
        get: ['collection', 'docId'],
        delete: ['collection', 'docId'],
        list: ['collection', 'query'],
    });
    const byUid = ([uid]: unknown[]) => ({ uid });
    const auth = instrumentApi<AuthApi>(
        'auth',
        createAuth(ctx, firestore, config.emailSender),
        log,
        {
            updateUser: byUid,
            setCustomUserClaims: byUid,
            disableUser: byUid,
            resetUserPassword: byUid,
            deleteUserPermanent: byUid,
        },
        {
            verifyIdToken: ['idToken'],
            createUser: ['params'],
            updateUser: ['uid', 'payload'],
            setCustomUserClaims: ['uid', 'claims'],
            disableUser: ['uid', 'disabled'],
            resetUserPassword: ['uid', 'newPassword'],
            verifyPasswordResetCode: ['oobCode'],
            requestPasswordReset: ['email', 'continueUrl'],
            confirmPasswordReset: ['oobCode', 'newPassword'],
            deleteUserPermanent: ['uid'],
        }
    );
    const byPath = ([path]: unknown[]) => ({ path });
    const storage = instrumentApi<StorageApi>('storage', createStorage(ctx), log, {
        upload: byPath,
        download: byPath,
        downloadStream: byPath,
        getMetadata: byPath,
        updateMetadata: byPath,
        delete: byPath,
        getDownloadUrl: byPath,
        signedUrl: byPath,
    }, {
        upload: ['path', 'data', 'options'],
        download: ['path'],
        downloadStream: ['path'],
        getMetadata: ['path'],
        updateMetadata: ['path', 'options'],
        list: ['query'],
        delete: ['path'],
        getDownloadUrl: ['path'],
        signedUrl: ['path', 'options'],
    });

    log.info('client created', {
        projectId: ctx.projectId,
        // A service-account identifier, not personal data; named so the e-mail masker leaves it intact
        serviceAccount: ctx.clientEmail,
        databaseName: ctx.databaseName,
        usersCollection: ctx.usersCollection,
        storageBucket: ctx.storageBucket,
        firestoreAuthSync: ctx.allowFirestoreAuthCollection !== false,
        emailSender: !!config.emailSender,
        logLevel: log.level,
    });

    return { auth, firestore, storage, getAccessToken };
}

export type FirebaseClient = ReturnType<typeof createFirebaseEdge>;

/**
 * Build a config from an env-like object. Works with Workers' `env`,
 * `process.env`, `Deno.env.toObject()`, etc.
 * Reads FB_PROJECT_ID, FB_CLIENT_EMAIL, FB_PRIVATE_KEY_ID,
 * FB_PRIVATE_KEY, FB_API_KEY and optionally FB_STORAGE_BUCKET, FB_RESEND_API_KEY + FB_RESEND_EMAIL_FROM,
 * and FB_LOG_LEVEL (`error` | `warn` | `info` | `debug` | `trace`) to opt in to diagnostic logging.
 *
 * @param env - The environment variables record mapping string keys to values.
 * @param overrides - Optional configuration properties to override values from the environment.
 * @returns A fully constructed FirebaseConfig object.
 */
export function configFromEnv(
    env: Record<string, string | undefined>,
    overrides: Partial<FirebaseConfig> = {}
): FirebaseConfig {
    const logLevel = env.FB_LOG_LEVEL?.trim().toLowerCase();
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
        // Unrecognised values are passed through so createFirebaseEdge can warn about the typo
        ...(logLevel ? { logger: isLogLevel(logLevel) ? logLevel : (logLevel as never) } : {}),
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

export { consoleSink } from './logger';
export type { LogLevel, LogEntry, LogSink, LoggerOptions } from './logger';

export { generateDocId } from './utils';
export { resendEmailSender } from './email';
