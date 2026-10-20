import { FirebaseError } from './errors';
import type { Context } from './types';
import {
  assertObjectName,
  buildMultipart,
  formatSigningTimestamp,
  sha256Hex,
  bytesToHex,
  toBytes,
  toStorageObject,
  uriEncode,
} from './utils.storage';

import { SignedUrlOptions, StorageApi, StorageData, StorageListQuery, StorageObject, UpdateMetadataOptions, UploadOptions } from './types/storage';

const STORAGE_API = 'https://storage.googleapis.com/storage/v1';
const STORAGE_UPLOAD_API = 'https://storage.googleapis.com/upload/storage/v1';
const STORAGE_HOST = 'storage.googleapis.com';
const RESUMABLE_THRESHOLD = 8 * 1024 * 1024;
const MAX_SIGNED_URL_SECONDS = 604800; // 7 days (V4 limit)
const TOKEN_KEY = 'firebaseStorageDownloadTokens';

export const SCOPE_STORAGE = 'https://www.googleapis.com/auth/devstorage.read_write';


/**
 * Creates a Cloud Storage client for the Firebase project's bucket using the
 * Cloud Storage JSON API with service-account credentials.
 * Note: this is administrative access. Firebase Security Rules do not apply.
 */
export function createStorage(ctx: Context): StorageApi {
  const bucket = ctx.storageBucket;
  const bucketBase = `${STORAGE_API}/b/${encodeURIComponent(bucket)}/o`;
  const uploadBase = `${STORAGE_UPLOAD_API}/b/${encodeURIComponent(bucket)}/o`;
  const objectUrl = (path: string) => `${bucketBase}/${encodeURIComponent(path)}`;

  async function request(url: string, init: RequestInit, fallback: string): Promise<Response> {
    const token = await ctx.getAccessToken(SCOPE_STORAGE);
    const res = await ctx.fetchFn(url, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(init.headers ?? {}),
      },
    });
    if (!res.ok && res.status !== 404) {
      const err: any = await res.json().catch(() => ({}));
      throw new FirebaseError(
        err.error?.errors?.[0]?.reason || 'STORAGE_ERROR',
        err.error?.message || fallback,
        res.status
      );
    }
    return res;
  }

  const notFound = (what: string) => new FirebaseError('NOT_FOUND', `${what} not found`, 404);

  async function upload(
    path: string,
    data: StorageData,
    options: UploadOptions = {}
  ): Promise<StorageObject> {
    assertObjectName(path);
    const { bytes, defaultType } = await toBytes(data);
    const contentType = options.contentType ?? defaultType;

    const metadata: Record<string, string> = { ...(options.metadata ?? {}) };
    if (options.downloadToken) {
      metadata[TOKEN_KEY] =
        typeof options.downloadToken === 'string' ? options.downloadToken : crypto.randomUUID();
    }
    const resource: Record<string, unknown> = { name: path, contentType };
    if (options.cacheControl !== undefined) resource.cacheControl = options.cacheControl;
    if (options.contentDisposition !== undefined) resource.contentDisposition = options.contentDisposition;
    if (options.contentEncoding !== undefined) resource.contentEncoding = options.contentEncoding;
    if (Object.keys(metadata).length) resource.metadata = metadata;

    const params = new URLSearchParams();
    if (options.ifGenerationMatch !== undefined) {
      params.set('ifGenerationMatch', String(options.ifGenerationMatch));
    }

    let res: Response;
    if (bytes.length > RESUMABLE_THRESHOLD) {
      params.set('uploadType', 'resumable');
      const init = await request(
        `${uploadBase}?${params}`,
        {
          method: 'POST',
          headers: {
            'X-Upload-Content-Type': contentType,
            'X-Upload-Content-Length': String(bytes.length),
          },
          body: JSON.stringify(resource),
        },
        'Storage upload failed'
      );
      const session = init.headers.get('Location');
      if (init.status === 404) throw notFound(`Bucket ${bucket}`);
      if (!session) throw new FirebaseError('STORAGE_ERROR', 'Storage did not return an upload session URL');
      res = await request(
        session,
        { method: 'PUT', headers: { 'Content-Type': contentType }, body: bytes as BodyInit },
        'Storage upload failed'
      );
    } else {
      params.set('uploadType', 'multipart');
      const multipart = buildMultipart(resource, bytes, contentType);
      res = await request(
        `${uploadBase}?${params}`,
        {
          method: 'POST',
          headers: { 'Content-Type': multipart.contentType },
          body: multipart.body as BodyInit,
        },
        'Storage upload failed'
      );
    }
    if (res.status === 404) throw notFound(`Bucket ${bucket}`);
    return toStorageObject(await res.json());
  }

  async function downloadResponse(path: string): Promise<Response | null> {
    assertObjectName(path);
    const res = await request(`${objectUrl(path)}?alt=media`, { method: 'GET' }, 'Storage download failed');
    return res.status === 404 ? null : res;
  }

  async function download(path: string): Promise<Uint8Array | null> {
    const res = await downloadResponse(path);
    return res ? new Uint8Array(await res.arrayBuffer()) : null;
  }

  async function downloadStream(path: string): Promise<ReadableStream<Uint8Array> | null> {
    const res = await downloadResponse(path);
    return res ? (res.body as ReadableStream<Uint8Array> | null) ?? new Blob([]).stream() : null;
  }

  async function getMetadata(path: string): Promise<StorageObject | null> {
    assertObjectName(path);
    const res = await request(objectUrl(path), { method: 'GET' }, 'Storage metadata read failed');
    return res.status === 404 ? null : toStorageObject(await res.json());
  }

  async function updateMetadata(path: string, options: UpdateMetadataOptions): Promise<StorageObject> {
    assertObjectName(path);
    const res = await request(
      objectUrl(path),
      { method: 'PATCH', body: JSON.stringify(options) },
      'Storage metadata update failed'
    );
    if (res.status === 404) throw notFound(`Object ${path}`);
    return toStorageObject(await res.json());
  }

  async function list(query: StorageListQuery = {}) {
    const params = new URLSearchParams();
    if (query.prefix) params.set('prefix', query.prefix);
    if (query.delimiter) params.set('delimiter', query.delimiter);
    params.set('maxResults', String(Math.min(query.limit || 100, 1000)));
    if (query.pageToken) params.set('pageToken', query.pageToken);

    const res = await request(`${bucketBase}?${params}`, { method: 'GET' }, 'Storage list failed');
    if (res.status === 404) throw notFound(`Bucket ${bucket}`);
    const body: any = await res.json();
    return {
      objects: ((body.items ?? []) as any[]).map(toStorageObject),
      prefixes: (body.prefixes ?? []) as string[],
      nextPageToken: body.nextPageToken as string | undefined,
    };
  }

  async function remove(path: string): Promise<void> {
    assertObjectName(path);
    await request(objectUrl(path), { method: 'DELETE' }, 'Storage delete failed');
  }

  async function getDownloadUrl(path: string): Promise<string> {
    let meta = await getMetadata(path);
    if (!meta) throw notFound(`Object ${path}`);
    let token = meta.metadata[TOKEN_KEY]?.split(',')[0];
    if (!token) {
      token = crypto.randomUUID();
      meta = await updateMetadata(path, { metadata: { [TOKEN_KEY]: token } });
    }
    return (
      `https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(bucket)}` +
      `/o/${encodeURIComponent(path)}?alt=media&token=${token}`
    );
  }

  async function signedUrl(path: string, options: SignedUrlOptions = {}): Promise<string> {
    assertObjectName(path);
    const method = options.method ?? 'GET';
    const expiresIn = options.expiresIn ?? 3600;
    if (!Number.isInteger(expiresIn) || expiresIn < 1 || expiresIn > MAX_SIGNED_URL_SECONDS) {
      throw new FirebaseError(
        'INVALID_ARGUMENT',
        `expiresIn must be an integer between 1 and ${MAX_SIGNED_URL_SECONDS} seconds`
      );
    }

    const now = options.now ?? new Date();
    const timestamp = formatSigningTimestamp(now);
    const scope = `${timestamp.slice(0, 8)}/auto/storage/goog4_request`;

    const headers: Array<[string, string]> = [['host', STORAGE_HOST]];
    if (options.contentType) headers.push(['content-type', options.contentType.trim()]);
    headers.sort((a, b) => (a[0] < b[0] ? -1 : 1));
    const signedHeaders = headers.map(([k]) => k).join(';');

    const query: Array<[string, string]> = [
      ['X-Goog-Algorithm', 'GOOG4-RSA-SHA256'],
      ['X-Goog-Credential', `${ctx.clientEmail}/${scope}`],
      ['X-Goog-Date', timestamp],
      ['X-Goog-Expires', String(expiresIn)],
      ['X-Goog-SignedHeaders', signedHeaders],
    ];
    if (options.responseDisposition) {
      query.push(['response-content-disposition', options.responseDisposition]);
    }
    const canonicalQuery = query
      .map(([k, v]) => [uriEncode(k), uriEncode(v)] as const)
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([k, v]) => `${k}=${v}`)
      .join('&');

    const canonicalPath = `/${bucket}/${uriEncode(path, false)}`;
    const canonicalRequest = [
      method,
      canonicalPath,
      canonicalQuery,
      headers.map(([k, v]) => `${k}:${v}`).join('\n'),
      '',
      signedHeaders,
      'UNSIGNED-PAYLOAD',
    ].join('\n');

    const stringToSign = ['GOOG4-RSA-SHA256', timestamp, scope, await sha256Hex(canonicalRequest)].join('\n');
    const signature = bytesToHex(await ctx.sign(new TextEncoder().encode(stringToSign)));

    return `https://${STORAGE_HOST}${canonicalPath}?${canonicalQuery}&X-Goog-Signature=${signature}`;
  }

  return {
    bucket,
    upload,
    download,
    downloadStream,
    getMetadata,
    updateMetadata,
    list,
    delete: remove,
    getDownloadUrl,
    signedUrl,
  };
}
