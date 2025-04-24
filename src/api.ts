export { PanDomainAuthentication } from './panda';

export type Authenticated = {
    success: true,
    shouldRefreshCredentials: boolean,
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

export type AuthenticationResult = Authenticated
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

export const gracePeriodInMillis = 24 * 60 * 60 * 1000;

export type ValidateUserFn = (user: User) => boolean;

export function guardianValidation(user: User): boolean {
    const isGuardianUser = user.email.indexOf('guardian.co.uk') !== -1;
    return isGuardianUser && user.multifactor;
}