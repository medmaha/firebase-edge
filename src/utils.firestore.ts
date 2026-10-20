import { FirebaseError } from './errors';
import { base64UrlEncode } from './utils';

/** Field paths with special characters must be wrapped in backticks. */
export function toFieldPath(key: string): string {
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)
        ? key
        : '`' + key.replace(/\\/g, '\\\\').replace(/`/g, '\\`') + '`';
}

export function fieldPathSegments(path: string): string[] {
    const segments: string[] = [];
    let segment = '';
    let quoted = false;
    let escaped = false;

    for (const char of path) {
        if (escaped) {
            segment += char;
            escaped = false;
        } else if (quoted && char === '\\') {
            escaped = true;
        } else if (char === '`') {
            quoted = !quoted;
        } else if (char === '.' && !quoted) {
            segments.push(segment);
            segment = '';
        } else {
            segment += char;
        }
    }
    segments.push(segment);
    return segments;
}

export function getFieldValue(fields: Record<string, any>, fieldPath: string): any {
    let current = fields;
    const segments = fieldPathSegments(fieldPath);

    for (let i = 0; i < segments.length; i++) {
        const value = current[segments[i]];
        if (value === undefined) return undefined;
        if (i === segments.length - 1) return value;
        current = value.mapValue?.fields;
        if (!current) return undefined;
    }
}

export function encodePageToken(queryKey: string, values: any[]): string {
    return base64UrlEncode(
        new TextEncoder().encode(JSON.stringify({ version: 1, queryKey, values }))
    );
}

export function decodePageToken(token: string, queryKey: string, valueCount: number): any[] {
    try {
        if (!/^[A-Za-z0-9_-]+$/.test(token)) throw new Error('Invalid token encoding');
        const base64 = token.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
        const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
        const decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        if (
            decoded.version !== 1 ||
            decoded.queryKey !== queryKey ||
            !Array.isArray(decoded.values) ||
            decoded.values.length !== valueCount ||
            decoded.values.some((value: unknown) => value === null || typeof value !== 'object')
        ) {
            throw new Error('Incompatible token');
        }
        return decoded.values;
    } catch {
        throw new FirebaseError(
            'INVALID_PAGE_TOKEN',
            'Invalid or incompatible Firestore page token'
        );
    }
}

export function encodeFields(data: Record<string, any>): Record<string, any> {
    const fields: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
        if (value === undefined) continue; // Firestore has no `undefined`
        fields[key] = toFirestoreValue(value);
    }
    return fields;
}

/**
 * Converts a standard JavaScript value into its Firestore typed value representation.
 * @param value - The JavaScript value to convert.
 */
export function toFirestoreValue(value: any): Record<string, any> {
    if (value === null || value === undefined) return { nullValue: null };
    if (typeof value === 'string') return { stringValue: value };
    if (typeof value === 'boolean') return { booleanValue: value };
    if (typeof value === 'bigint') return { integerValue: value.toString() };
    if (typeof value === 'number') {
        return Number.isSafeInteger(value)
            ? { integerValue: String(value) }
            : { doubleValue: value };
    }
    if (value instanceof Date) return { timestampValue: value.toISOString() };
    if (Array.isArray(value)) {
        return { arrayValue: { values: value.map((v) => toFirestoreValue(v)) } };
    }
    if (typeof value === 'object') return { mapValue: { fields: encodeFields(value) } };
    return { stringValue: String(value) };
}

/**
 * Converts a Firestore typed value representation back into a standard JavaScript value.
 * @param v - The Firestore value object.
 */
export function fromFirestoreValue(v: any): any {
    if (v == null) return null;
    if ('nullValue' in v) return null;
    if ('stringValue' in v) return v.stringValue;
    if ('booleanValue' in v) return v.booleanValue;
    if ('integerValue' in v) return Number(v.integerValue);
    if ('doubleValue' in v) return v.doubleValue;
    if ('timestampValue' in v) return new Date(v.timestampValue);
    if ('arrayValue' in v) return (v.arrayValue.values ?? []).map(fromFirestoreValue);
    if ('mapValue' in v) return decodeFields(v.mapValue.fields ?? {});
    return v.referenceValue ?? v.bytesValue ?? v.geoPointValue ?? null;
}

export function decodeFields(fields: Record<string, any>): Record<string, any> {
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(fields)) out[k] = fromFirestoreValue(v);
    return out;
}
