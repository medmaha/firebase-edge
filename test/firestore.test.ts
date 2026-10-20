import { describe, expect, it } from 'vitest';
import { FirebaseError } from '../src/errors';
import { createFirestore } from '../src/firestore';
import { fromFirestoreValue, toFirestoreValue } from '../src/utils.firestore';
import {
  DOC_NAME,
  FS_DOCS,
  apiError,
  commitWrites,
  jsonResponse,
  makeCtx,
  routes,
} from './helpers';


describe('toFirestoreValue', () => {
  it('maps primitives', () => {
    expect(toFirestoreValue('x')).toEqual({ stringValue: 'x' });
    expect(toFirestoreValue(true)).toEqual({ booleanValue: true });
    expect(toFirestoreValue(false)).toEqual({ booleanValue: false });
    expect(toFirestoreValue(null)).toEqual({ nullValue: null });
    expect(toFirestoreValue(undefined)).toEqual({ nullValue: null });
  });

  it('writes safe integers as integerValue strings', () => {
    expect(toFirestoreValue(0)).toEqual({ integerValue: '0' });
    expect(toFirestoreValue(42)).toEqual({ integerValue: '42' });
    expect(toFirestoreValue(-7)).toEqual({ integerValue: '-7' });
    expect(toFirestoreValue(Number.MAX_SAFE_INTEGER)).toEqual({
      integerValue: String(Number.MAX_SAFE_INTEGER),
    });
  });

  it('writes floats and unsafe integers as doubleValue', () => {
    expect(toFirestoreValue(1.5)).toEqual({ doubleValue: 1.5 });
    expect(toFirestoreValue(2 ** 60)).toEqual({ doubleValue: 2 ** 60 });
  });

  it('writes bigint as integerValue', () => {
    expect(toFirestoreValue(9007199254740993n)).toEqual({ integerValue: '9007199254740993' });
  });

  it('writes Date as timestampValue', () => {
    expect(toFirestoreValue(new Date('2026-01-01T00:00:00Z'))).toEqual({
      timestampValue: '2026-01-01T00:00:00.000Z',
    });
  });

  it('writes arrays and nested objects, dropping undefined fields', () => {
    expect(toFirestoreValue([1, 'a', [true]])).toEqual({
      arrayValue: {
        values: [
          { integerValue: '1' },
          { stringValue: 'a' },
          { arrayValue: { values: [{ booleanValue: true }] } },
        ],
      },
    });
    expect(toFirestoreValue({ a: 1, skip: undefined, b: { c: 'x' } })).toEqual({
      mapValue: {
        fields: {
          a: { integerValue: '1' },
          b: { mapValue: { fields: { c: { stringValue: 'x' } } } },
        },
      },
    });
  });
});

describe('fromFirestoreValue', () => {
  it('decodes each value type', () => {
    expect(fromFirestoreValue({ nullValue: null })).toBeNull();
    expect(fromFirestoreValue({ stringValue: 'x' })).toBe('x');
    expect(fromFirestoreValue({ booleanValue: false })).toBe(false);
    expect(fromFirestoreValue({ integerValue: '42' })).toBe(42);
    expect(fromFirestoreValue({ doubleValue: 1.5 })).toBe(1.5);
    expect(fromFirestoreValue({ timestampValue: '2026-01-01T00:00:00Z' })).toEqual(
      new Date('2026-01-01T00:00:00Z')
    );
    expect(fromFirestoreValue({ referenceValue: 'projects/p/x' })).toBe('projects/p/x');
  });

  it('treats empty arrays and maps (which omit values/fields) as empty', () => {
    expect(fromFirestoreValue({ arrayValue: {} })).toEqual([]);
    expect(fromFirestoreValue({ mapValue: {} })).toEqual({});
  });

  it('round-trips encoded data', () => {
    const data = {
      s: 'x',
      n: 3,
      f: 2.25,
      b: true,
      nil: null,
      d: new Date('2026-05-05T05:05:05Z'),
      arr: [1, 'two', { three: 3 }],
      nested: { deep: { deeper: [false] } },
    };
    expect(fromFirestoreValue(toFirestoreValue(data))).toEqual(data);
  });
});

describe('firestore.set', () => {
  it('replaces the whole document by default (no update mask)', async () => {
    const { ctx, calls } = makeCtx(routes([[`PATCH ${FS_DOCS}/orders/abc`, () => ({})]]));
    await createFirestore(ctx).set('orders', 'abc', { total: 42.5, status: 'new' });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(`${FS_DOCS}/orders/abc`);
    expect(calls[0].headers.Authorization).toBe('Bearer test-token');
    expect(calls[0].body).toEqual({
      fields: { total: { doubleValue: 42.5 }, status: { stringValue: 'new' } },
    });
  });

  it('merge: sends an update mask with only the provided fields', async () => {
    const { ctx, calls } = makeCtx(routes([[`PATCH ${FS_DOCS}/orders/abc`, () => ({})]]));
    await createFirestore(ctx).set('orders', 'abc', { status: 'paid', total: 1 }, { merge: true });

    const url = new URL(calls[0].url);
    expect(url.searchParams.getAll('updateMask.fieldPaths')).toEqual(['status', 'total']);
  });

  it('merge: backtick-quotes field names that are not simple identifiers', async () => {
    const { ctx, calls } = makeCtx(routes([[`PATCH ${FS_DOCS}/c/d`, () => ({})]]));
    await createFirestore(ctx).set(
      'c',
      'd',
      { 'a.b': 1, 'has space': 2, '9lives': 3, ok_name: 4 },
      { merge: true }
    );

    const paths = new URL(calls[0].url).searchParams.getAll('updateMask.fieldPaths');
    expect(paths).toEqual(['`a.b`', '`has space`', '`9lives`', 'ok_name']);
  });

  it('merge: is a no-op when there is nothing to write (an empty mask would replace the doc)', async () => {
    const { ctx, fn } = makeCtx();
    await createFirestore(ctx).set('c', 'd', {}, { merge: true });
    await createFirestore(ctx).set('c', 'd', { a: undefined }, { merge: true });
    expect(fn).not.toHaveBeenCalled();
  });

  it('skips undefined fields', async () => {
    const { ctx, calls } = makeCtx(routes([[`PATCH ${FS_DOCS}/c/d`, () => ({})]]));
    await createFirestore(ctx).set('c', 'd', { a: 1, b: undefined });
    expect(Object.keys(calls[0].body.fields)).toEqual(['a']);
  });

  it('supports nested collection paths and encodes the document id', async () => {
    const { ctx, calls } = makeCtx(
      routes([[`PATCH ${FS_DOCS}/users/u1/orders/a%20b%2Fc`, () => ({})]])
    );
    await createFirestore(ctx).set('users/u1/orders', 'a b/c', { x: 1 });
    expect(calls[0].url).toBe(`${FS_DOCS}/users/u1/orders/a%20b%2Fc`);
  });

  it('throws a FirebaseError carrying the Firestore status and message', async () => {
    const { ctx } = makeCtx(() =>
      apiError('Missing permissions', 403, { status: 'PERMISSION_DENIED' })
    );
    const err = await createFirestore(ctx).set('c', 'd', { a: 1 }).catch((e) => e);

    expect(err).toBeInstanceOf(FirebaseError);
    expect(err).toMatchObject({ code: 'PERMISSION_DENIED', message: 'Missing permissions', status: 403 });
  });

  it('falls back to a generic error when the error body is not JSON', async () => {
    const { ctx } = makeCtx(() => new Response('oops', { status: 500 }));
    await expect(createFirestore(ctx).set('c', 'd', { a: 1 })).rejects.toMatchObject({
      code: 'FIRESTORE_ERROR',
      message: 'Firestore write failed',
      status: 500,
    });
  });
});

describe('firestore.update', () => {
  const commitRoute: [string, () => any] = [`POST ${FS_DOCS}:commit`, () => ({})];

  it('commits a masked partial update', async () => {
    const { ctx, calls } = makeCtx(routes([commitRoute]));
    await createFirestore(ctx).update('users', 'u1', { status: 'active', age: 30 });

    const [write] = commitWrites(calls);
    expect(write.update.name).toBe(DOC_NAME('users/u1'));
    expect(write.update.fields).toEqual({
      status: { stringValue: 'active' },
      age: { integerValue: '30' },
    });
    expect(write.updateMask).toEqual({ fieldPaths: ['status', 'age'] });
    expect(write.updateTransforms).toBeUndefined();
    expect(calls[0].headers.Authorization).toBe('Bearer test-token');
  });

  it('adds atomic increment transforms (integer and double)', async () => {
    const { ctx, calls } = makeCtx(routes([commitRoute]));
    await createFirestore(ctx).update('users', 'u1', { a: 1 }, { increments: { count: 1, ratio: 0.5 } });

    const [write] = commitWrites(calls);
    expect(write.updateTransforms).toEqual([
      { fieldPath: 'count', increment: { integerValue: '1' } },
      { fieldPath: 'ratio', increment: { doubleValue: 0.5 } },
    ]);
  });

  it('with only increments, uses an empty mask so no other field is touched', async () => {
    const { ctx, calls } = makeCtx(routes([commitRoute]));
    await createFirestore(ctx).update('users', 'u1', {}, { increments: { count: 1 } });

    const [write] = commitWrites(calls);
    expect(write.update.fields).toEqual({});
    expect(write.updateMask).toEqual({ fieldPaths: [] });
  });

  it('quotes special field names in mask and transforms', async () => {
    const { ctx, calls } = makeCtx(routes([commitRoute]));
    await createFirestore(ctx).update('c', 'd', { 'a.b': 1 }, { increments: { 'x y': 1 } });

    const [write] = commitWrites(calls);
    expect(write.updateMask.fieldPaths).toEqual(['`a.b`']);
    expect(write.updateTransforms[0].fieldPath).toBe('`x y`');
  });

  it('throws a FirebaseError on failure', async () => {
    const { ctx } = makeCtx(() => apiError('nope', 400, { status: 'INVALID_ARGUMENT' }));
    await expect(createFirestore(ctx).update('c', 'd', { a: 1 })).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
      status: 400,
    });
  });
});

describe('firestore.get', () => {
  it('returns decoded document data', async () => {
    const { ctx, calls } = makeCtx(
      routes([
        [
          `GET ${FS_DOCS}/users/u1`,
          () => ({
            name: DOC_NAME('users/u1'),
            fields: {
              email: { stringValue: 'a@b.c' },
              count: { integerValue: '3' },
              createdAt: { timestampValue: '2026-01-01T00:00:00Z' },
              tags: { arrayValue: { values: [{ stringValue: 'x' }] } },
            },
          }),
        ],
      ])
    );

    const doc = await createFirestore(ctx).get('users', 'u1');
    expect(doc).toEqual({
      email: 'a@b.c',
      count: 3,
      createdAt: new Date('2026-01-01T00:00:00Z'),
      tags: ['x'],
    });
    expect(calls[0].headers.Authorization).toBe('Bearer test-token');
  });

  it('returns {} for a document with no fields', async () => {
    const { ctx } = makeCtx(() => ({ name: DOC_NAME('users/u1') }));
    expect(await createFirestore(ctx).get('users', 'u1')).toEqual({});
  });

  it('returns null when the document does not exist', async () => {
    const { ctx } = makeCtx(() => apiError('Not found', 404, { status: 'NOT_FOUND' }));
    expect(await createFirestore(ctx).get('users', 'missing')).toBeNull();
  });

  it('throws on other errors', async () => {
    const { ctx } = makeCtx(() => apiError('denied', 403, { status: 'PERMISSION_DENIED' }));
    await expect(createFirestore(ctx).get('users', 'u1')).rejects.toMatchObject({
      code: 'PERMISSION_DENIED',
    });
  });
});

describe('firestore.list', () => {
  it('returns decoded documents with ids and uses a default limit', async () => {
    const { ctx, calls } = makeCtx(
      routes([
        [
          `POST ${FS_DOCS}:runQuery`,
          () => [
            {
              document: {
                name: DOC_NAME('users/u1'),
                fields: {
                  email: { stringValue: 'ada@example.com' },
                  age: { integerValue: '36' },
                },
              },
            },
            { readTime: '2026-01-01T00:00:00Z' },
            {
              document: {
                name: DOC_NAME('users/u2'),
                fields: { disabled: { booleanValue: true } },
              },
            },
          ],
        ],
      ])
    );

    await expect(createFirestore(ctx).list('users')).resolves.toEqual({
      documents: [
        { id: 'u1', email: 'ada@example.com', age: 36 },
        { id: 'u2', disabled: true },
      ],
      nextPageToken: undefined,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(`${FS_DOCS}:runQuery`);
    expect(calls[0].body).toEqual({
      structureQuery: {
        limit: 100,
        from: [{ collectionId: 'users' }],
        orderBy: [
          {
            direction: 'ASCENDING',
            field: { fieldPath: '__name__' },
          },
        ],
      },
    });
  });

  it('applies filters and ordering from the query options', async () => {
    const { ctx, calls } = makeCtx(
      routes([[`POST ${FS_DOCS}:runQuery`, () => []]])
    );

    await expect(
      createFirestore(ctx).list('orders', {
        field: 'status',
        value: 'paid',
        op: 'EQUAL',
        limit: 25,
        orderBy: 'createdAt',
        direction: 'DESCENDING',
      })
    ).resolves.toEqual({
      "documents": [],
      "nextPageToken": undefined,
    });
    expect(calls[0].body).toEqual({
      structureQuery: {
        limit: 25,
        from: [{ collectionId: 'orders' }],
        where: {
          fieldFilter: {
            op: 'EQUAL',
            value: { stringValue: 'paid' },
            field: { fieldPath: 'status' },
          },
        },
        orderBy: [
          {
            direction: 'DESCENDING',
            field: { fieldPath: 'createdAt' },
          },
          {
            direction: 'DESCENDING',
            field: { fieldPath: '__name__' },
          },
        ],
      },
    });
  });

  it('caps the requested limit at 500', async () => {
    const { ctx, calls } = makeCtx(routes([[`POST ${FS_DOCS}:runQuery`, () => []]]));
    await createFirestore(ctx).list('users', { limit: 1000 });
    expect(calls[0].body.structureQuery.limit).toBe(500);
  });

  it('returns a stable cursor token and uses it to fetch the next ordered page', async () => {
    let page = 0;
    const { ctx, calls } = makeCtx(() => {
      page++;
      return [
        {
          document: {
            name: DOC_NAME(`orders/o${page * 2 - 1}`),
            fields: {
              createdAt: { timestampValue: `2026-01-0${page}T00:00:00Z` },
              total: { integerValue: '10' },
            },
          },
        },
        {
          document: {
            name: DOC_NAME(`orders/o${page * 2}`),
            fields: {
              createdAt: { timestampValue: `2026-01-0${page}T00:00:00Z` },
              total: { integerValue: '20' },
            },
          },
        },
      ];
    });
    const firestore = createFirestore(ctx);
    const query = { limit: 2, orderBy: 'createdAt', direction: 'DESCENDING' as const };

    const firstPage = await firestore.list('orders', query);
    expect(firstPage.documents).toEqual([
      { id: 'o1', createdAt: new Date('2026-01-01T00:00:00Z'), total: 10 },
      { id: 'o2', createdAt: new Date('2026-01-01T00:00:00Z'), total: 20 },
    ]);
    expect(firstPage.nextPageToken).toBeTruthy();
    expect(calls[0].body.structureQuery.orderBy).toEqual([
      { direction: 'DESCENDING', field: { fieldPath: 'createdAt' } },
      { direction: 'DESCENDING', field: { fieldPath: '__name__' } },
    ]);

    const secondPage = await firestore.list('orders', {
      ...query,
      pageToken: firstPage.nextPageToken,
    });
    expect(secondPage.documents).toEqual([
      { id: 'o3', createdAt: new Date('2026-01-02T00:00:00Z'), total: 10 },
      { id: 'o4', createdAt: new Date('2026-01-02T00:00:00Z'), total: 20 },
    ]);
    expect(calls[1].body.structureQuery.startAt).toEqual({
      values: [
        { timestampValue: '2026-01-01T00:00:00Z' },
        { referenceValue: DOC_NAME('orders/o2') },
      ],
      before: false,
    });
  });

  it('uses document name ordering by default and rejects a token for another query', async () => {
    const { ctx, fn } = makeCtx(() => [
      { document: { name: DOC_NAME('users/u1'), fields: { email: { stringValue: 'a@b.co' } } } },
    ]);
    const firestore = createFirestore(ctx);
    const firstPage = await firestore.list('users', { limit: 1 });

    expect(firstPage.nextPageToken).toBeTruthy();
    expect(fn.mock.calls[0][1]?.body).toContain('"fieldPath":"__name__"');
    await expect(
      firestore.list('members', { limit: 1, pageToken: firstPage.nextPageToken })
    ).rejects.toMatchObject({ code: 'INVALID_PAGE_TOKEN' });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('rejects malformed page tokens', async () => {
    const { ctx, fn } = makeCtx();
    await expect(
      createFirestore(ctx).list('users', { pageToken: 'not a token' })
    ).rejects.toMatchObject({ code: 'INVALID_PAGE_TOKEN' });
    expect(fn).not.toHaveBeenCalled();
  });

  it('throws on query errors', async () => {
    const { ctx } = makeCtx(() => apiError('denied', 403, { status: 'PERMISSION_DENIED' }));
    await expect(createFirestore(ctx).list('users')).rejects.toMatchObject({
      code: 'PERMISSION_DENIED',
      status: 403,
    });
  });
});

describe('firestore.delete', () => {
  it('sends a DELETE for the document', async () => {
    const { ctx, calls } = makeCtx(routes([[`DELETE ${FS_DOCS}/users/u1`, () => ({})]]));
    await createFirestore(ctx).delete('users', 'u1');
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe('DELETE');
  });

  it('treats a missing document as a no-op', async () => {
    const { ctx } = makeCtx(() => jsonResponse({ error: { message: 'x' } }, 404));
    await expect(createFirestore(ctx).delete('users', 'missing')).resolves.toBeUndefined();
  });

  it('throws on other errors', async () => {
    const { ctx } = makeCtx(() => apiError('boom', 500));
    await expect(createFirestore(ctx).delete('users', 'u1')).rejects.toBeInstanceOf(FirebaseError);
  });
});
