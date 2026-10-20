

export interface FirestoreListQuery {
    /** Field path to filter on. */
    field?: string;
    /** Value to compare with the field. */
    value?: unknown;
    /** Maximum documents to return in this page. Defaults to 100 and is capped at 500. */
    limit?: number;
    /** Field path used to order results. Document name is used by default. */
    orderBy?: string;
    /** Sort direction. Defaults to `ASCENDING`. */
    direction?: 'ASCENDING' | 'DESCENDING';
    op?:
    | 'IN'
    | 'EQUAL'
    | 'NOT_EQUAL'
    | 'LESS_THAN'
    | 'LESS_THAN_OR_EQUAL'
    | 'GREATER_THAN'
    | 'GREATER_THAN_OR_EQUAL'
    | 'ARRAY_CONTAINS';
    /** Opaque cursor returned by the previous page. */
    pageToken?: string;
}

export interface FirestoreApi {
    /**
     * Writes or overwrites a document in Firestore.
     * 
     * Default: replaces the whole document.
     * With `{ merge: true }`: only the provided top-level fields are written
     * (the document is created if missing).
     * 
     * @param collection The Firestore collection path.
     * @param docId The unique document identifier.
     * @param data The data payload to write.
     * @param options Configuration options, such as `{ merge: true }`.
     */
    set(
        collection: string,
        docId: string,
        data: Record<string, any>,
        options?: { merge?: boolean }
    ): Promise<void>;

    /**
     * Updates a document in Firestore.
     * Merges `data` into the document (creating it if needed) in one atomic commit.
     * `increments: { field: n }` atomically adds n to a numeric field.
     * 
     * @param collection The Firestore collection path.
     * @param docId The unique document identifier.
     * @param data The fields to update.
     * @param options Optional transform options, such as atomic increments.
     */
    update(
        collection: string,
        docId: string,
        data?: Record<string, any>,
        options?: { increments?: Record<string, number> }
    ): Promise<void>;

    /**
     * Retrieves a single document from Firestore.
     * 
     * @template T The expected document data structure type.
     * @param collection The Firestore collection path.
     * @param docId The unique document identifier.
     * @returns Returns the decoded document data, or null if it doesn't exist.
     */
    get<T = Record<string, any>>(collection: string, docId: string): Promise<T | null>;

    /**
     * Queries and lists documents from a collection with optional filtering, ordering, limiting, and pagination.
     * 
     * @template T The array type of the resulting documents.
     * @param collection The Firestore collection path.
     * @param query Optional query parameters and pagination token.
     * @returns Returns one page of documents and an optional opaque token for fetching the next page.
     */
    list<T = Array<Record<string, unknown>>>(
        collection: string,
        query?: FirestoreListQuery
    ): Promise<{ documents: T; nextPageToken?: string }>;

    /**
     * Deletes a document from Firestore. Deleting a missing document is a safe no-op.
     * 
     * @param collection The Firestore collection path.
     * @param docId The unique document identifier.
     */
    delete(collection: string, docId: string): Promise<void>;
}
