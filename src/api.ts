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

export type FreshlyAuthenticated = {
    success: true,
    // Cookie has not expired yet, so no need to refresh credentials.
    shouldRefreshCredentials: false,
    user: User
}
export type Authenticated = {
    success: true,
    // Cookie has expired: we're in the grace period.
    // Endpoints that can refresh credentials should do so,
    // and those that cannot should tell the user to do so.
    shouldRefreshCredentials: true,
    mustRefreshByEpochTimeMillis: number,
    user: User
}
export type Unauthenticated = {
    success: false,
    reason: 'no-cookie' | 'bad-cookie' | 'expired-cookie' | 'unknown'
}
export type Unauthorised = {
    success: false,
    reason: 'bad-user',
    user: User
}

export type AuthenticationResult = FreshlyAuthenticated
    | Authenticated
    | Unauthenticated
    | Unauthorised

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