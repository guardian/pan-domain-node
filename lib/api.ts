export { PanDomainAuthentication } from './PanDomainAuthentication';

export enum AuthenticationStatus {
    INVALID_COOKIE = 'Invalid Cookie',
    EXPIRED = 'Expired',
    NOT_AUTHORISED = 'Not Authorised',
    AUTHORISED = 'Authorised'
}

export interface User {
    firstName: string,
    lastName: string,
    email: string,
    avatarUrl?: string
}

export interface AuthenticatedUser {
    user: User,
    authenticatingSystem: string,
    authenticatedIn: string[],
    expires: number,
    multiFactor: boolean
}

export interface AuthenticationResult {
    status: AuthenticationStatus,
    user?: AuthenticatedUser 
}

export type ValidateUserFn = (user: AuthenticatedUser) => Boolean;

export function guardianValidation(user: AuthenticatedUser): Boolean {
    return (user.user.email.indexOf('guardian.co.uk') !== -1) && user.multiFactor;
}