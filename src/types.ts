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
  /** Optional minimum password length requirement for authentication. Defaults: 6 */
  minAuthPasswordLength?: number;
  /** Optional email sender function used to notify users (e.g., for password resets). */
  emailSender?: EmailSender;
  /** Custom fetch implementation (testing / proxies). Defaults to global fetch. */
  fetchFn?: typeof fetch;
}


/** @internal */
export interface Context {
  projectId: string;
  apiKey: string;
  databaseName: string
  usersCollection: string;
  allowFirestoreAuthCollection?: boolean
  minAuthPasswordLength?: number
  fetchFn: typeof fetch;
  getAccessToken(scope: string): Promise<string>;
}
