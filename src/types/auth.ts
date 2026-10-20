export interface CreateUserPayload {
    email?: string;
    password: string;
    displayName?: string;
    disabled?: boolean;
    emailVerified?: boolean;
    /** Custom claims to set on the Auth user (e.g. `{ role: 'admin' }`). */
    claims?: Record<string, any>;
    phoneNumber?: string | null;
}

export interface AuthApi {
    /**
     * Verifies a Firebase ID token and returns the corresponding user details and custom claims.
     * @param idToken The JWT ID token to verify.
     * @returns An object containing the user's UID, email, verification status, and claims.
     * @throws {FirebaseError} If the token is invalid, expired, or the user is disabled.
     */
    verifyIdToken(idToken: string): Promise<{ uid: string; [key: string]: any }>;

    /**
     * Updates an existing user's profile and credentials across both Auth and Firestore.
     * @param uid The unique identifier of the user to update.
     * @param payload The fields to update.
     * @throws {FirebaseError} If the user cannot be found.
     */
    updateUser(uid: string, payload: Record<string, any>): Promise<void>;

    /**
     * Creates a new user in Firebase Auth and mirrors their profile data in Firestore.
     * @param params Configuration parameters for the new user (email, password, claims, etc.).
     * @returns An object containing the newly created user's UID.
     * @throws {FirebaseError} If validation fails or creation errors occur.
     */
    createUser(params: CreateUserPayload): Promise<{ uid: string }>;

    /**
     * Sets custom user claims for a specific user.
     * @param uid The unique identifier of the user.
     * @param claims An object containing the custom claims to assign.
     */
    setCustomUserClaims(uid: string, claims: Record<string, any>): Promise<void>;

    /**
     * Toggles disabled status (or sets it explicitly) and mirrors it to Firestore.
     * @param uid The unique identifier of the user.
     * @param disabled Optional explicit boolean status to set for the user.
     * @returns An object containing the user's UID and their updated disabled state.
     */
    disableUser(uid: string, disabled?: boolean): Promise<{ uid: string; disabled: boolean }>;

    /**
     * Admin-initiated password reset: sets the password, revokes existing sessions, and notifies the user via email.
     * @param uid The unique identifier of the user.
     * @param newPassword The new password to set.
     * @returns An object containing the user's UID and whether the notification email was sent successfully.
     */
    resetUserPassword(
        uid: string,
        newPassword: string
    ): Promise<{ uid: string; emailSent: boolean }>;

    /**
     * Verifies a password reset out-of-band (OOB) code.
     * @param oobCode The out-of-band code sent to the user's email.
     * @returns An object containing the email address associated with the code.
     * @throws {FirebaseError} If the code is invalid or not a password reset type.
     */
    verifyPasswordResetCode(oobCode: string): Promise<{ email: string }>;

    /**
     * Requests a password reset email to be sent to the user.
     * Never reveals whether the email is registered; Firebase sends the email itself.
     * @param email The email address requesting the reset.
     * @param continueUrl Optional URL to redirect the user after password reset.
     */
    requestPasswordReset(email: string, continueUrl?: string): Promise<void>;

    /**
     * Confirms and finalizes a password reset using an out-of-band (OOB) code and a new password.
     * @param oobCode The out-of-band code sent to the user's email.
     * @param newPassword The new password to set.
     * @returns An object containing the email address of the updated user.
     */
    confirmPasswordReset(oobCode: string, newPassword: string): Promise<{ email: string }>;

    /**
     * Permanently deletes a user from both Auth and Firestore.
     * @param uid The unique identifier of the user to delete.
     * @returns An object indicating success.
     */
    deleteUserPermanent(uid: string): Promise<{ success: boolean }>;
}
