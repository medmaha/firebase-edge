export class FirebaseError extends Error {
    code: string;
    status?: number;
    constructor(code: string, message?: string, status?: number) {
        super(message ?? code);
        this.name = 'FirebaseError';
        this.code = code;
        this.status = status;
    }
}

export function invalidIdTokenError(): FirebaseError {
    return new FirebaseError('INVALID_ID_TOKEN', 'Invalid or expired token', 401);
}
