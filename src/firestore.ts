import { FirebaseError } from './errors';
import type { Context } from './types';
import { encodeDocPath } from './utils';
import { decodeFields, decodePageToken, encodeFields, encodePageToken, getFieldValue, toFieldPath, toFirestoreValue } from './utils.firestore';

const FIRESTORE_BASE = 'https://firestore.googleapis.com/v1';
const SCOPE_DATASTORE = 'https://www.googleapis.com/auth/datastore';


/**
 * Creates a Firestore API client wrapper with methods for reading, writing, updating, and querying documents.
 * @param ctx The application context containing configuration, database name, and token providers.
 */
export function createFirestore(ctx: Context): FirestoreApi {
  async function request(url: string, init: RequestInit, fallback: string): Promise<Response> {
    const token = await ctx.getAccessToken(SCOPE_DATASTORE);
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
        err.error?.status || 'FIRESTORE_ERROR',
        err.error?.message || fallback,
        res.status
      );
    }
    return res;
  }

  const docsBase = `${FIRESTORE_BASE}/projects/${ctx.projectId}/databases/(${ctx.databaseName.replace(/\(\)/g, "")})/documents`;

  async function set(
    collection: string,
    docId: string,
    data: Record<string, any>,
    options: { merge?: boolean } = {}
  ): Promise<void> {
    const fields = encodeFields(data);

    let query = '';
    if (options.merge) {
      const keys = Object.keys(fields);
      if (keys.length === 0) return; // empty mask would be a full replace
      query =
        '?' +
        keys
          .map((k) => `updateMask.fieldPaths=${encodeURIComponent(toFieldPath(k))}`)
          .join('&');
    }

    const res = await request(
      `${docsBase}/${encodeDocPath(collection, docId)}${query}`,
      { method: 'PATCH', body: JSON.stringify({ fields }) },
      'Firestore write failed'
    );
    if (res.status === 404) throw new FirebaseError('NOT_FOUND', 'Firestore write failed', 404);
  }

  async function update(
    collection: string,
    docId: string,
    data: Record<string, any> = {},
    options: { increments?: Record<string, number> } = {}
  ): Promise<void> {
    const fields = encodeFields(data);
    const updateTransforms = Object.entries(options.increments ?? {}).map(
      ([field, amount]) => ({
        fieldPath: toFieldPath(field),
        increment: Number.isInteger(amount)
          ? { integerValue: String(amount) }
          : { doubleValue: amount },
      })
    );

    const write: Record<string, any> = {
      update: {
        name: `projects/${ctx.projectId}/databases/(${ctx.databaseName})/documents/${collection}/${docId}`,
        fields,
      },
      // Explicit mask: only touch the listed fields, never replace the document
      updateMask: { fieldPaths: Object.keys(fields).map(toFieldPath) },
    };
    if (updateTransforms.length) write.updateTransforms = updateTransforms;

    await request(
      `${docsBase}:commit`,
      { method: 'POST', body: JSON.stringify({ writes: [write] }) },
      'Firestore update failed'
    );
  }

  async function get<T = Record<string, any>>(
    collection: string,
    docId: string
  ): Promise<T | null> {
    const res = await request(
      `${docsBase}/${encodeDocPath(collection, docId)}`,
      { method: 'GET' },
      'Firestore read failed'
    );
    if (res.status === 404) return null;
    const doc: any = await res.json();
    return decodeFields(doc.fields ?? {}) as T;
  }

  async function list<T = Array<Record<string, unknown>>>(
    collection: string,
    query: FirestoreListQuery = {}
  ): Promise<{ documents: T; nextPageToken?: string }> {
    const limit = Math.min(query.limit || 100, 500);
    const direction = query.direction ?? 'ASCENDING';

    const orderFields = query.orderBy
      ? [
        { fieldPath: query.orderBy, direction },
        ...(query.orderBy === '__name__' ? [] : [{ fieldPath: '__name__', direction }]),
      ]
      : [{ fieldPath: '__name__', direction: 'ASCENDING' }];

    const structureQuery = makeListQuery(collection, query);
    structureQuery.limit = limit;
    structureQuery.orderBy = orderFields.map(({ fieldPath, direction }) => ({
      direction,
      field: { fieldPath },
    }));

    const queryKey = JSON.stringify({
      collection,
      where: structureQuery.where,
      orderBy: orderFields,
    });
    const valueCount = orderFields.length;
    if (query.pageToken !== undefined) {
      structureQuery.startAt = {
        values: decodePageToken(query.pageToken, queryKey, valueCount),
        before: false,
      };
    }

    const rows = await runListQuery(collection, structureQuery);
    const documents = decodeListRows(rows) as T;
    let nextPageToken: string | undefined;

    if (rows.length === limit) {
      const lastDocument = rows[rows.length - 1].document;
      const cursorValues = orderFields.map(({ fieldPath }) => {
        if (fieldPath === '__name__') return { referenceValue: lastDocument.name };
        const value = getFieldValue(lastDocument.fields || {}, fieldPath);
        if (value === undefined) {
          throw new FirebaseError(
            'QUERY_FAILED',
            `Firestore result is missing ordered field ${fieldPath}`
          );
        }
        return value;
      });
      nextPageToken = encodePageToken(queryKey, cursorValues);
    }

    return { documents, nextPageToken };
  }

  async function remove(collection: string, docId: string): Promise<void> {
    await request(
      `${docsBase}/${encodeDocPath(collection, docId)}`,
      { method: 'DELETE' },
      'Firestore delete failed'
    );
  }

  async function runListQuery(collection: string, structureQuery: any): Promise<any[]> {
    const res = await request(
      `${docsBase}:runQuery`,
      { method: 'POST', body: JSON.stringify({ structureQuery }) },
      'Firestore document query failed'
    );
    if (!res.ok) {
      throw new FirebaseError(
        'QUERY_FAILED',
        `Failed to perform firestore query of collection ${collection}`
      );
    }
    const rows: any[] = await res.json();
    return rows.filter((row) => row.document);
  }

  function decodeListRows(rows: any[]): Array<Record<string, any>> {
    return rows.map((row) => ({
      ...decodeFields(row.document.fields || {}),
      id: row.document.name.split('/').pop(),
    }));
  }

  return { set, update, get, list, delete: remove };
}

/**
 * @Internal
 * Builds the structured query payload for listing and filtering documents.
 * Supports a maximum of 500 records per request.
 */
function makeListQuery(collection: string, query: FirestoreListQuery): any {
  const structureQuery: any = {
    limit: Math.min(query.limit || 100, 500),
    from: [{ collectionId: collection }],
  };

  if (query.field && query.op) {
    structureQuery.where = {
      fieldFilter: {
        op: query.op,
        value: toFirestoreValue(query.value),
        field: { fieldPath: query.field },
      },
    };
  }

  if (query.orderBy) {
    structureQuery.orderBy = [
      {
        direction: query.direction ?? 'ASCENDING',
        field: { fieldPath: query.orderBy },
      },
    ];
  }
  return structureQuery;
}

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
