export class FirebaseError extends Error {
    code: string;
    status?: number;
    /** The underlying error, when this one wraps or replaces another. */
    cause?: unknown;
    constructor(code: string, message?: string, status?: number, options?: { cause?: unknown }) {
        super(message ?? code);
        this.name = 'FirebaseError';
        this.code = code;
        this.status = status;
        if (options && 'cause' in options) this.cause = options.cause;
    }
}
