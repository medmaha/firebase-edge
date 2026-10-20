import { createAuth } from './auth';
import { createFirestore } from './firestore';
import { createTokenProvider } from './google-auth';
import { resendEmailSender } from './email';
import type { Context, FirebaseConfig } from './types';

export { FirebaseError } from './errors';
export { generateDocId } from './utils';
export { resendEmailSender } from './email';
export type { FirebaseConfig, EmailSender, EmailMessage } from './types';

/**
 * Creates a client. Construct once per isolate/process and reuse it:
 * token and key caches live inside the client.
 * 
 * @param config - The Firebase configuration object containing credentials and options.
 * @returns An object containing initialized auth, firestore, and token provider utilities.
 * @throws {Error} If any required configuration values are missing.
 */
export function createGF(config: FirebaseConfig) {
  const required = ['projectId', 'clientEmail', 'privateKey', 'privateKeyId', 'apiKey'] as const;
  const missing = required.filter((k) => !config[k]);
  if (missing.length) {
    throw new Error(`createGF: missing config values: ${missing.join(', ')}`);
  }

  // Wrapped so an unbound global fetch never throws "Illegal invocation" on Workers
  const fetchFn: typeof fetch =
    config.fetchFn ?? ((...args: Parameters<typeof fetch>) => fetch(...args));

  const getAccessToken = createTokenProvider(
    {
      projectId: config.projectId,
      clientEmail: config.clientEmail,
      privateKeyId: config.privateKeyId,
      privateKey: config.privateKey.replace(/^"|"$/g, '').replace(/\\n/g, '\n'),
    },
    fetchFn
  );

  const ctx: Context = {
    projectId: config.projectId,
    apiKey: config.apiKey,
    databaseName: config.databaseName ?? "default",
    usersCollection: config.usersCollection ?? 'users',
    fetchFn: fetchFn,
    getAccessToken,
  };

  const firestore = createFirestore(ctx);
  const auth = createAuth(ctx, firestore, config.emailSender);

  return { auth, firestore, getAccessToken };
}

export type FirebaseClient = ReturnType<typeof createGF>;

/**
 * Build a config from an env-like object. Works with Workers' `env`,
 * `process.env`, `Deno.env.toObject()`, etc.
 * Reads GF_PROJECT_ID, GF_CLIENT_EMAIL, GF_PRIVATE_KEY_ID,
 * GF_PRIVATE_KEY, GF_API_KEY and optionally GF_RESEND_API_KEY + GF_RESEND_EMAIL_FROM.
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
    projectId: env.GF_PROJECT_ID!,
    clientEmail: env.GF_CLIENT_EMAIL!,
    privateKeyId: env.GF_PRIVATE_KEY_ID!,
    privateKey: env.GF_PRIVATE_KEY!,
    apiKey: env.GF_API_KEY!,
    emailSender:
      env.GF_RESEND_API_KEY && env.GF_RESEND_EMAIL_FROM
        ? resendEmailSender({ apiKey: env.GF_RESEND_API_KEY, from: env.GF_RESEND_EMAIL_FROM })
        : undefined,
    ...overrides,
  };
}
