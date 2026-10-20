/** Data accepted by `storage.upload()`. */
export type StorageData = string | ArrayBuffer | ArrayBufferView | Blob;

export interface StorageObject {
    name: string;
    bucket: string;
    /** Size in bytes. */
    size: number;
    contentType?: string;
    cacheControl?: string;
    contentDisposition?: string;
    contentEncoding?: string;
    /** Custom metadata (string values only). */
    metadata: Record<string, string>;
    generation?: string;
    metageneration?: string;
    md5Hash?: string;
    crc32c?: string;
    etag?: string;
    /** Epoch milliseconds. */
    createdAt?: number;
    /** Epoch milliseconds. */
    updatedAt?: number;
}

export interface UploadOptions {
    /** Defaults to the Blob's type, `text/plain; charset=utf-8` for strings, else `application/octet-stream`. */
    contentType?: string;
    cacheControl?: string;
    contentDisposition?: string;
    contentEncoding?: string;
    /** Custom metadata. */
    metadata?: Record<string, string>;
    /** `true` generates a Firebase download token; a string uses that token. Enables `getDownloadUrl()` links. */
    downloadToken?: boolean | string;
    /** Write only if the object's generation matches. `0` means "only if it does not exist yet". */
    ifGenerationMatch?: number | string;
}

export interface UpdateMetadataOptions {
    contentType?: string;
    cacheControl?: string;
    contentDisposition?: string;
    contentEncoding?: string;
    /** Custom metadata to merge. Set a key to `null` to remove it. */
    metadata?: Record<string, string | null>;
}

export interface StorageListQuery {
    prefix?: string;
    /** Usually "/" to list one "folder" level; sub-folders come back in `prefixes`. */
    delimiter?: string;
    /** Default 100, max 1000. */
    limit?: number;
    pageToken?: string;
}

export interface SignedUrlOptions {
    /** Default "GET". */
    method?: 'GET' | 'PUT' | 'DELETE' | 'HEAD';
    /** Lifetime in seconds. Default 3600, max 604800 (7 days). */
    expiresIn?: number;
    /** For PUT: the client must send exactly this Content-Type header. */
    contentType?: string;
    /** Sets the Content-Disposition of the response (e.g. `attachment; filename="a.pdf"`). */
    responseDisposition?: string;
    /** Signing time. Testing aid; defaults to now. */
    now?: Date;
}

export interface StorageApi {
    /** The bucket this client operates on. */
    readonly bucket: string;
    /** Uploads an object up to 8 MiB using a multipart request. Resumable uploads are not supported. */
    upload(path: string, data: StorageData, options?: UploadOptions): Promise<StorageObject>;
    /** Returns the object's bytes, or `null` if it does not exist. */
    download(path: string): Promise<Uint8Array | null>;
    /** Like `download()` but streams the body; `null` if it does not exist. */
    downloadStream(path: string): Promise<ReadableStream<Uint8Array> | null>;
    /** Returns `null` if the object does not exist. */
    getMetadata(path: string): Promise<StorageObject | null>;
    updateMetadata(path: string, options: UpdateMetadataOptions): Promise<StorageObject>;
    list(query?: StorageListQuery): Promise<{
        objects: StorageObject[];
        prefixes: string[];
        nextPageToken?: string;
    }>;
    /** Deleting a missing object is a no-op. */
    delete(path: string): Promise<void>;
    /** Firebase-style tokenized download URL (the kind `getDownloadURL()` returns). Creates a token if needed. */
    getDownloadUrl(path: string): Promise<string>;
    /** Time-limited V4 signed URL for GET/PUT/DELETE/HEAD, signed locally with the service-account key. */
    signedUrl(path: string, options?: SignedUrlOptions): Promise<string>;
}
