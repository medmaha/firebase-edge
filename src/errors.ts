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
