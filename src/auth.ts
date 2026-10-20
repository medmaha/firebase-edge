import { FirebaseError } from './errors';
import { createIdentityClient } from './identity';
import type { Context, EmailSender } from './types';
import { AuthApi, CreateUserPayload } from './types/auth';
import type { FirestoreApi } from './types/firestore';
import { assertEmailOrPhoneNumber, assertPassword, normalizeEmail, serializeClaims } from './utils.auth';


/**
 * Initializes and returns an authentication client with methods for user management, token verification, and password resets.
 */
export function createAuth(
  ctx: Context,
  fs: FirestoreApi,
  emailSender?: EmailSender
): AuthApi {
  const idt = createIdentityClient(ctx);
  const fsAuthCollection = ctx.allowFirestoreAuthCollection === false ? null : ctx.usersCollection;

  async function touchUserByEmail(email: string | undefined, data: Record<string, any>) {
    if (!email || !fsAuthCollection) return;
    const user = await idt.lookupUser({ email: [normalizeEmail(email)!] });
    if (user) await fs.update(fsAuthCollection, user.localId, data);
  }

  async function verifyIdToken(idToken: string): Promise<{ uid: string;[key: string]: any }> {
    let data: any;
    try {
      data = await idt.call('/accounts:lookup', { idToken }, 'apiKey');
    } catch {
      throw new FirebaseError('INVALID_ID_TOKEN', 'Invalid or expired token', 401);
    }
    const user = data.users?.[0];
    if (!user) throw new FirebaseError('INVALID_ID_TOKEN', 'Invalid or expired token', 401);
    if (user.disabled) throw new FirebaseError('USER_DISABLED', 'User is disabled', 403);

    let customClaims: Record<string, any> = {};
    if (user.customAttributes) {
      try {
        customClaims = JSON.parse(user.customAttributes);
      } catch { }
    }

    // Claims first so they can never override uid/email
    return {
      ...customClaims,
      uid: user.localId,
      email: user.email,
      emailVerified: !!user.emailVerified,
    };
  }

  async function createUser(params: CreateUserPayload): Promise<{ uid: string }> {
    assertEmailOrPhoneNumber(params.email, params.phoneNumber);
    assertPassword(params.password, ctx.minAuthPasswordLength);

    const claims = params.claims ? serializeClaims(params.claims) : undefined;

    const emailAddress = normalizeEmail(params.email!)

    const body: Record<string, any> = {
      email: emailAddress,
      password: params.password,
      displayName: params.displayName,
      emailVerified: !!params.emailVerified,
      disableUser: !!params.disabled,
    };
    if (params.phoneNumber?.trim()) body.phoneNumber = params.phoneNumber.trim();

    const data = await idt.call<any>('/accounts', body, 'admin');
    if (!data.localId) throw new FirebaseError('CREATE_USER_FAILED', 'Failed to create user');
    const uid: string = data.localId;

    try {
      if (fsAuthCollection) {
        const now = Date.now();
        const fbUser: any = {
          email: body.email,
          displayName: params.displayName,
          phoneNumber: body.phoneNumber ?? null,
          disabled: !!params.disabled,
          disabledAt: params.disabled ? now : null,
          passwordResetCount: 0,
          createdAt: now,
          updatedAt: now,
        }
        await fs.set(
          fsAuthCollection,
          uid,
          fbUser,
          { merge: true }
        );
      }
      if (claims) {
        await idt.call('/accounts:update', { localId: uid, customAttributes: claims }, 'admin');
      }
    } catch (err) {
      // Roll back so we don't leave a half-created user
      await idt.call('/accounts:delete', { localId: uid }, 'admin').catch(() => { });
      if (fsAuthCollection) {
        await fs.delete(fsAuthCollection, uid).catch(() => { });
      }
      throw err;
    }

    return { uid };
  }

  async function setCustomUserClaims(uid: string, claims: Record<string, any>): Promise<void> {
    await idt.call(
      '/accounts:update',
      { localId: uid, customAttributes: serializeClaims(claims) },
      'admin'
    );
  }

  async function updateUser(uid: string, payload: Record<string, any>): Promise<void> {
    const user = await idt.lookupUser({ localId: [uid] });
    if (!user) throw new FirebaseError('USER_NOT_FOUND', 'User not found', 404);

    const firestorePayload = fsAuthCollection ? { ...payload } : {};
    delete firestorePayload.password;
    delete firestorePayload.disableUser;

    const authPayload: Record<string, any> = { localId: uid };
    for (const field of ['email', 'displayName', 'password']) {
      if (field in payload) authPayload[field] = payload[field];
    }

    const disabledValue =
      'disableUser' in payload
        ? Boolean(payload.disableUser)
        : 'disabled' in payload
          ? Boolean(payload.disabled)
          : undefined;

    if (disabledValue !== undefined) {
      authPayload.disableUser = disabledValue;
      firestorePayload.disabled = disabledValue;
    }

    // Update the firestore users collection first
    if (fsAuthCollection) await fs.update(fsAuthCollection, uid, firestorePayload);

    // Only make the auth update when necessary
    if (Object.keys(authPayload).length > 1) {
      await idt.call('/accounts:update', authPayload, 'admin');
    }
  }

  async function disableUser(uid: string, disabled?: boolean) {
    let target = disabled;
    if (target === undefined) {
      const user = await idt.lookupUser({ localId: [uid] });
      if (!user) throw new FirebaseError('USER_NOT_FOUND', 'User not found', 404);
      target = !user.disabled;
    }

    await idt.call('/accounts:update', { localId: uid, disableUser: target }, 'admin');
    if (fsAuthCollection) {
      const now = Date.now();
      await fs.update(fsAuthCollection, uid, {
        updatedAt: now,
        disabled: target,
        disabledAt: target ? now : null,
      });
    }
    return { uid, disabled: target };
  }

  async function deleteUserPermanent(uid: string) {
    try {
      if (fsAuthCollection) {
        // deleting firestore because auth delete is irreversible and is the only link to firestore
        await fs.delete(fsAuthCollection, uid)
      }
      await idt.call('/accounts:delete', { localId: uid }, 'admin')
      return { success: true }
    } catch (error) {
      if (String(error).includes("USER_NOT_FOUND")) return { success: true }
      throw error
    }
  }

  async function resetUserPassword(uid: string, newPassword: string) {
    assertPassword(newPassword, ctx.minAuthPasswordLength);

    const user = await idt.lookupUser({ localId: [uid] });
    if (!user) throw new FirebaseError('USER_NOT_FOUND', 'User not found', 404);

    await idt.call(
      '/accounts:update',
      {
        localId: uid,
        password: newPassword,
        validSince: String(Math.floor(Date.now() / 1000)), // revoke existing sessions
      },
      'admin'
    );

    if (fsAuthCollection) {
      const now = Date.now();
      await fs.update(
        fsAuthCollection,
        uid,
        { updatedAt: now, passwordResetAt: now },
        { increments: { passwordResetCount: 1 } }
      );
    }
    let emailSent = false;
    if (user.email && emailSender) {
      try {
        emailSent =
          (await emailSender({
            to: user.email,
            subject: 'Your password was reset',
            text:
              'Hello,\n\nYour account password has just been reset by an administrator. ' +
              'You have been signed out of existing sessions.\n\n' +
              'If you did not expect this, please contact support immediately.',
          })) !== false;
      } catch (err) {
        console.error('emailSender failed:', err);
      }
    }

    return { uid, emailSent };
  }

  async function requestPasswordReset(email: string, continueUrl?: string): Promise<void> {
    if (!email) return
    const normalized = normalizeEmail(email)!;

    const user = await idt.lookupUser({ email: [normalized] });
    if (!user || user.disabled) return;

    try {
      await idt.call(
        '/accounts:sendOobCode',
        {
          requestType: 'PASSWORD_RESET',
          email: normalized,
          ...(continueUrl ? { continueUrl } : {}),
        },
        'apiKey'
      );
    } catch (err) {
      if (err instanceof FirebaseError && err.code === 'EMAIL_NOT_FOUND') return;
      throw err;
    }

    const now = Date.now();
    if (fsAuthCollection) await fs.update(fsAuthCollection, user.localId, { updatedAt: now, passwordResetLinkSentAt: now });
  }

  async function verifyPasswordResetCode(oobCode: string): Promise<{ email: string }> {
    const data = await idt.call<any>('/accounts:resetPassword', { oobCode }, 'apiKey');
    if (data.requestType && data.requestType !== 'PASSWORD_RESET') {
      throw new FirebaseError('INVALID_OOB_CODE', 'Not a password reset code');
    }
    const now = Date.now();
    await touchUserByEmail(data.email, { updatedAt: now, passwordResetLinkVerifiedAt: now });
    return { email: data.email };
  }

  async function confirmPasswordReset(oobCode: string, newPassword: string) {
    assertPassword(newPassword, ctx.minAuthPasswordLength);
    const data = await idt.call<{ email: string }>(
      '/accounts:resetPassword',
      { oobCode, newPassword },
      'apiKey'
    );
    const now = Date.now();
    await touchUserByEmail(data.email, { updatedAt: now, passwordResetConfirmedAt: now });
    return { email: data.email };
  }

  return {
    verifyIdToken,
    updateUser,
    createUser,
    setCustomUserClaims,
    disableUser,
    resetUserPassword,
    verifyPasswordResetCode,
    requestPasswordReset,
    confirmPasswordReset,
    deleteUserPermanent
  };
}

