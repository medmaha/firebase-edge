/**
 * Encodes binary data into a URL-safe Base64 string (without padding).
 *
 * @param data - The ArrayBuffer or Uint8Array to encode.
 * @returns The URL-safe Base64 encoded string.
 */
export function base64UrlEncode(data: ArrayBuffer | Uint8Array): string {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Converts a PEM-formatted cryptographic key string into a DER ArrayBuffer.
 *
 * @param pem - The PEM-encoded string containing headers, footers, and base64 data.
 * @returns The raw DER binary representation as an ArrayBuffer.
 */
export function pemToDer(pem: string): ArrayBuffer {
    const base64 = pem.replace(/-----(BEGIN|END)[A-Z ]*-----/g, '').replace(/\s/g, '');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

/**
 * Generates a Firestore-style random document ID (default 20 characters, URL/path safe, unbiased).
 *
 * @param length - The desired length of the generated ID (defaults to 20).
 * @returns A cryptographically secure random ID string.
 */
export function generateDocId(length = 20): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const limit = 256 - (256 % chars.length);
    let id = '';
    while (id.length < length) {
        for (const byte of crypto.getRandomValues(new Uint8Array(length))) {
            if (byte < limit && id.length < length) id += chars[byte % chars.length];
        }
    }
    return id;
}

/**
 * Encodes a collection path and optional document ID into a safely URI-encoded path string.
 *
 * @param collection - The Firestore collection path (can include sub-collections).
 * @param docId - Optional unique document identifier.
 * @returns The URI-encoded document path string.
 */
export function encodeDocPath(collection: string, docId?: string): string {
    return [...collection.split('/'), docId]
        .filter(Boolean)
        .map((p) => encodeURIComponent(p!))
        .join('/');
}
