import { describe, expect, it } from 'vitest';
import { base64UrlEncode, encodeDocPath, generateDocId, pemToDer } from '../src/utils';

describe('generateDocId', () => {
    it('defaults to 20 alphanumeric characters', () => {
        expect(generateDocId()).toMatch(/^[A-Za-z0-9]{20}$/);
    });

    it('honours a custom length', () => {
        expect(generateDocId(5)).toHaveLength(5);
        expect(generateDocId(64)).toHaveLength(64);
        expect(generateDocId(0)).toBe('');
    });

    it('does not collide in a large sample', () => {
        const ids = new Set(Array.from({ length: 5000 }, () => generateDocId()));
        expect(ids.size).toBe(5000);
    });

    it('can produce every character of the alphabet', () => {
        const seen = new Set(generateDocId(20000));
        expect(seen.size).toBe(62);
    });
});

describe('base64UrlEncode', () => {
    it('uses the URL-safe alphabet', () => {
        // standard base64 of these bytes is "+//+"
        expect(base64UrlEncode(new Uint8Array([251, 255, 254]))).toBe('-__-');
    });

    it('strips padding', () => {
        expect(base64UrlEncode(new Uint8Array([1]))).toBe('AQ');
        expect(base64UrlEncode(new Uint8Array([1, 2]))).toBe('AQI');
    });

    it('accepts an ArrayBuffer as well as a Uint8Array', () => {
        const bytes = new Uint8Array([10, 20, 30]);
        expect(base64UrlEncode(bytes.buffer)).toBe(base64UrlEncode(bytes));
    });
});

describe('pemToDer', () => {
    const bytes = Uint8Array.from({ length: 40 }, (_, i) => i * 6);
    const b64 = btoa(String.fromCharCode(...bytes));

    it.each(['PRIVATE KEY', 'RSA PRIVATE KEY', 'PUBLIC KEY'])('decodes a %s PEM', (label) => {
        const pem = `-----BEGIN ${label}-----\n${b64.slice(0, 30)}\n${b64.slice(30)}\n-----END ${label}-----\n`;
        expect(Array.from(new Uint8Array(pemToDer(pem)))).toEqual(Array.from(bytes));
    });
});

describe('encodeDocPath', () => {
    it('keeps collection separators and encodes the id', () => {
        expect(encodeDocPath('users', 'abc')).toBe('users/abc');
        expect(encodeDocPath('users/u1/orders', 'a b/c')).toBe('users/u1/orders/a%20b%2Fc');
    });
});
