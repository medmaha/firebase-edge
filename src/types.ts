import type { LogLevel, Logger, LoggerOptions } from './logger';

export interface EmailMessage {
    to: string;
    subject: string;
    text: string;
}

/** Return true if sent. Throwing or returning false never breaks the calling flow. */
export type EmailSender = (message: EmailMessage) => Promise<boolean | void>;

/**
 * Configuration options required to initialize the Firebase client.
 */
export interface FirebaseConfig {
    /** The Firebase project ID. */
    projectId: string;
    /** The service account email address. */
    clientEmail: string;
    /** PEM private key. Escaped "\n" sequences and wrapping quotes are handled. */
    privateKey: string;
    /** The private key ID associated with the service account. */
    privateKeyId: string;
    /** Web API key (used for public Identity Toolkit endpoints). */
    apiKey: string;
    /** When enabled, auth operations automatically update the corresponding firestore record in `usersCollection`. Defaults to true. */
    allowFirestoreAuthCollection?: boolean;
    /** Firestore database name. Default: "default" */
    databaseName?: string;
    /** Firestore collection holding user profile docs. Default: "users" */
    usersCollection?: string;
    /** Cloud Storage bucket used by `storage`. Default: `<projectId>.firebasestorage.app` (older projects: `<projectId>.appspot.com`). */
    storageBucket?: string;
    /** Optional minimum password length requirement for authentication. Defaults: 6 */
    minAuthPasswordLength?: number;
    /** Optional email sender function used to notify users (e.g., for password resets). */
    emailSender?: EmailSender;
    /** Custom fetch implementation (testing / proxies). Defaults to global fetch. */
    fetchFn?: typeof fetch;
    /**
     * Opt-in diagnostic logging. Off by default (nothing is emitted).
     * - a level: `'error' | 'warn' | 'info' | 'debug' | 'trace'` (logged to the console)
     * - `true`: shorthand for `'info'`
     * - `{ level?, sink? }`: route entries to your own logger
     * Credentials are always redacted. `'trace'` additionally records request/response
     * payloads (application data is NOT redacted), so use it for local debugging only.
     */
    logger?: LogLevel | boolean | LoggerOptions;
}

/** @internal */
export interface Context {
    projectId: string;
    apiKey: string;
    databaseName: string;
    usersCollection: string;
    allowFirestoreAuthCollection?: boolean;
    minAuthPasswordLength?: number;
    storageBucket: string;
    clientEmail: string;
    fetchFn: typeof fetch;
    /** Diagnostic logger. Absent means logging is disabled. */
    log?: Logger;
    getAccessToken(scope: string): Promise<string>;
    /** Signs bytes with the service-account private key (RSA-SHA256). */
    sign(data: Uint8Array): Promise<ArrayBuffer>;
}
