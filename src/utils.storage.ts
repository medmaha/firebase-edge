import { FirebaseError } from './errors';
import { StorageData, StorageObject } from './types/storage';
import { generateDocId } from './utils';

/** Validates an object name (GCS rules: 1-1024 bytes, no leading slash, no "." / ".." segments). */
export function assertObjectName(name: string): void {
    const bad =
        typeof name !== 'string' ||
        name.length === 0 ||
        name.startsWith('/') ||
        new TextEncoder().encode(name).length > 1024 ||
        /[\r\n]/.test(name) ||
        name.split('/').some((seg) => seg === '.' || seg === '..');
    if (bad) {
        throw new FirebaseError(
            'INVALID_ARGUMENT',
            `Invalid storage object name: ${JSON.stringify(name)}`
        );
    }
}

/** Normalizes upload input to bytes plus a default content type. */
export async function toBytes(
    data: StorageData
): Promise<{ bytes: Uint8Array; defaultType: string }> {
    if (typeof data === 'string') {
        return { bytes: new TextEncoder().encode(data), defaultType: 'text/plain; charset=utf-8' };
    }
    if (typeof Blob !== 'undefined' && data instanceof Blob) {
        return {
            bytes: new Uint8Array(await data.arrayBuffer()),
            defaultType: data.type || 'application/octet-stream',
        };
    }
    if (data instanceof ArrayBuffer) {
        return { bytes: new Uint8Array(data), defaultType: 'application/octet-stream' };
    }
    if (ArrayBuffer.isView(data)) {
        return {
            bytes: new Uint8Array(data.buffer, data.byteOffset, data.byteLength),
            defaultType: 'application/octet-stream',
        };
    }
    throw new FirebaseError('INVALID_ARGUMENT', 'Unsupported upload data type');
}

/** Builds a `multipart/related` body: JSON metadata part followed by the media part. */
export function buildMultipart(
    metadata: Record<string, unknown>,
    bytes: Uint8Array,
    contentType: string
): { body: Uint8Array; contentType: string } {
    const boundary = `firebase-edge-${generateDocId(24)}`;
    const enc = new TextEncoder();
    const head = enc.encode(
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n` +
            `${JSON.stringify(metadata)}\r\n` +
            `--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`
    );
    const tail = enc.encode(`\r\n--${boundary}--`);
    const body = new Uint8Array(head.length + bytes.length + tail.length);
    body.set(head, 0);
    body.set(bytes, head.length);
    body.set(tail, head.length + bytes.length);
    return { body, contentType: `multipart/related; boundary=${boundary}` };
}

export function bytesToHex(data: ArrayBuffer | Uint8Array): string {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
}

export async function sha256Hex(text: string): Promise<string> {
    return bytesToHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}

/** RFC 3986 percent-encoding as required by GCS V4 signing. */
export function uriEncode(value: string, encodeSlash = true): string {
    const encoded = encodeURIComponent(value).replace(
        /[!'()*]/g,
        (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`
    );
    return encodeSlash ? encoded : encoded.replace(/%2F/g, '/');
}

/** `YYYYMMDDTHHMMSSZ` */
export function formatSigningTimestamp(date: Date): string {
    return date
        .toISOString()
        .replace(/[-:]/g, '')
        .replace(/\.\d{3}Z$/, 'Z');
}

/** Converts a raw GCS object resource into the public `StorageObject` shape. */
export function toStorageObject(raw: any): StorageObject {
    const ms = (v?: string) => (v ? Date.parse(v) : undefined);
    return {
        name: raw.name,
        bucket: raw.bucket,
        size: Number(raw.size ?? 0),
        contentType: raw.contentType,
        cacheControl: raw.cacheControl,
        contentDisposition: raw.contentDisposition,
        contentEncoding: raw.contentEncoding,
        metadata: raw.metadata ?? {},
        generation: raw.generation,
        metageneration: raw.metageneration,
        md5Hash: raw.md5Hash,
        crc32c: raw.crc32c,
        etag: raw.etag,
        createdAt: ms(raw.timeCreated),
        updatedAt: ms(raw.updated),
    };
}
