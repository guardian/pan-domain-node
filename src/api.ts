export { PanDomainAuthentication } from './panda';

// We continue to consider the request authenticated for
// a period of time after the cookie expiry. This is to allow
// API requests which cannot directly send the user for re-auth to
// indicate to the user that they must take some action to refresh their
// credentials (usually, refreshing the page).

// Panda cookie:               issued     expires
//                             |          |
//                             |--1 hour--|
// Grace period:                          [------------- 24 hours ------]
// `success`:         --false-][-true-----------------------------------][-false-------->
// `shouldRefreshCredentials`  [-false---][-true------------------------]
export const gracePeriodInMillis = 24 * 60 * 60 * 1000;

// These are used to enforce the structure of the
// `AuthenticationResult` union types,
// but are not exported because they are too general.
interface Result {
    success: boolean
}
interface Success extends Result {
    // `success` is true when both these are true:
    // 1. we've verified that the cookie is signed by the correct private key
    //    and decoded a `User` from it
    // 2. we've validated the `User` using `ValidateUserFn`
    success: true,
    shouldRefreshCredentials: boolean,
    user: User
}
interface Failure extends Result {
    success: false,
    reason: string
}

// These are members of the `AuthenticationResult` union,
// so they are exported for use by library consumers.
export interface FreshSuccess extends Success {
    // Cookie has not expired yet, so no need to refresh credentials.
    shouldRefreshCredentials: false
}
export interface StaleSuccess extends Success {
    // Cookie has expired: we're in the grace period.
    // Endpoints that can refresh credentials should do so,
    // and those that cannot should tell the user to do so.
    shouldRefreshCredentials: true,
    mustRefreshByEpochTimeMillis: number
}
export interface UserValidationFailure extends Failure {
    reason: 'bad-user',
    user: User
}
export interface CookieFailure extends Failure {
    reason: 'no-cookie' | 'bad-cookie' | 'expired-cookie'
}
export interface UnknownFailure extends Failure {
    reason: 'unknown'
}

export type AuthenticationResult = FreshSuccess
    | StaleSuccess
    | CookieFailure
    | UserValidationFailure
    | UnknownFailure


export interface User {
    firstName: string,
    lastName: string,
    email: string,
    avatarUrl?: string,
    authenticatingSystem: string,
    authenticatedIn: string[],
    expires: number,
    multifactor: boolean
}

export type ValidateUserFn = (user: User) => boolean;

export function guardianValidation(user: User): boolean {
    const isGuardianUser = user.email.indexOf('guardian.co.uk') !== -1;
    return isGuardianUser && user.multifactor;
}