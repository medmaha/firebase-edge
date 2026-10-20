import { FirebaseError } from './errors';
import type { Context } from './types';

const IDENTITY_TOOLKIT_BASE = 'https://identitytoolkit.googleapis.com/v1';
export const SCOPE_IDENTITY = 'https://www.googleapis.com/auth/identitytoolkit';

/**
 * Creates an identity client for interacting with the Firebase Identity Toolkit API.
 * @param ctx - The application context containing configuration, credentials, and fetch implementation.
 */
export function createIdentityClient(ctx: Context) {
    /**
     * Makes an authenticated request to the Google Identity Toolkit API.
     * @template T - The expected response data type.
     * @param path - The API endpoint path.
     * @param body - The payload body to send with the request.
     * @param auth - The authentication mode ('admin' for service account, 'apiKey' for web API key).
     * @returns The parsed response data.
     * @throws {FirebaseError} If the request fails or returns an error.
     */
    async function call<T = any>(
        path: string,
        body: Record<string, any>,
        auth: 'admin' | 'apiKey'
    ): Promise<T> {
        let url: string;
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };

        if (auth === 'admin') {
            headers['Authorization'] = `Bearer ${await ctx.getAccessToken(SCOPE_IDENTITY)}`;
            url = `${IDENTITY_TOOLKIT_BASE}/projects/${ctx.projectId}${path}`;
        } else {
            url = `${IDENTITY_TOOLKIT_BASE}${path}?key=${encodeURIComponent(ctx.apiKey)}`;
        }

        const res = await ctx.fetchFn(url, { method: 'POST', headers, body: JSON.stringify(body) });
        const data: any = await res.json().catch(() => ({}));

        if (!res.ok || data.error) {
            const raw: string =
                data.error?.message || `Identity Toolkit request failed (${res.status})`;
            throw new FirebaseError(raw.split(' : ')[0].trim(), raw, res.status);
        }
        return data as T;
    }

    /**
     * Looks up a user account by their local ID or email address.
     * @param query - An object specifying user local IDs or email addresses to search for.
     * @returns The user record object if found, or null otherwise.
     */
    async function lookupUser(query: { localId?: string[]; email?: string[] }) {
        const data = await call<any>('/accounts:lookup', query, 'admin');
        return (data.users?.[0] as any) ?? null;
    }

    return { call, lookupUser };
}
