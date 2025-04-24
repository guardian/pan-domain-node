export { PanDomainAuthentication } from './panda';

export type AuthenticatedResult = {
    success: true,
    suggestCredentialsRefresh: boolean,
    user: User
}
export type UnauthenticatedResult = {
    success: false,
    reason: 'no-cookie' | 'bad-cookie' | 'expired-cookie' | 'bad-user' | 'unknown'
}
export type UnauthorisedResult = {
    success: false,
    reason: 'bad-user',
    user: User
}

export type AuthenticationResult = AuthenticatedResult
    | UnauthenticatedResult
    | UnauthorisedResult

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