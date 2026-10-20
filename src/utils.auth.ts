import { FirebaseError } from './errors';

const MIN_PASSWORD_LENGTH = 6; // Firebase default

/**
 * Normalizes an email address by trimming whitespace and converting to lowercase.
 */
export const normalizeEmail = (email: string) => email?.trim().toLowerCase() || null;

/**
 * Validates that a password meets Firebase's minimum length requirement.
 */
export function assertPassword(password: string, min = MIN_PASSWORD_LENGTH) {
    if (typeof password !== 'string' || password.length < min) {
        throw new FirebaseError('WEAK_PASSWORD', `Password must be at least ${min} characters`);
    }
}

/**
 * Validates that at least one identity field is provided.
 * Firebase requires either an email address or a phone number when creating a user.
 */
export function assertEmailOrPhoneNumber(email?: unknown, phoneNumber?: unknown) {
    const validate = (value?: unknown) => {
        if (typeof value === 'string' && Boolean(value.trim())) {
            return true;
        }
    };

    if (!validate(email) && !validate(phoneNumber)) {
        throw new FirebaseError(
            'IDENTITY_ASSERTION',
            'Email or phone number required to create user'
        );
    }
}

/**
 * Serializes custom claims and enforces Firebase's 1000-byte size limit.
 */
export function serializeClaims(claims: Record<string, any>): string {
    try {
        const serialized = JSON.stringify(claims ?? {});
        if (new TextEncoder().encode(serialized).length > 1000) {
            throw new FirebaseError('CLAIMS_TOO_LARGE', 'Custom claims must be 1000 bytes or less');
        }
        return serialized;
    } catch (error) {
        if (error instanceof FirebaseError) {
            throw error;
        }
        throw new FirebaseError('INVALID_DATATYPE', 'Custom claims must be valid JSON');
    }
}
