import * as cookie from 'cookie';

import {parseCookie, parseUser, sign, verifySignature} from './utils';
import {User, AuthenticationResult, ValidateUserFn, gracePeriodInMillis} from './api';
import { fetchPublicKey, PublicKeyHolder } from './fetch-public-key';
import { S3 } from "@aws-sdk/client-s3";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { AwsCredentialIdentityProvider } from "@aws-sdk/types";

export function createCookie(user: User, privateKey: string): string {
    let queryParams: string[] = [];

    queryParams.push("firstName=" + user.firstName);
    queryParams.push("lastName=" + user.lastName);
    queryParams.push("email=" + user.email);
    user.avatarUrl && queryParams.push("avatarUrl=" + user.avatarUrl);
    queryParams.push("system=" + user.authenticatingSystem);
    queryParams.push("authedIn=" + user.authenticatedIn.join(","));
    queryParams.push("expires=" + user.expires.toString());
    queryParams.push("multifactor=" + String(user.multifactor));
    const combined = queryParams.join("&");

    const queryParamsString = Buffer.from(combined).toString('base64');

    const signature = sign(combined, privateKey);

    return queryParamsString + "." + signature
}

export function verifyUser(pandaCookie: string | undefined, publicKey: string, currentTime: Date, validateUser: ValidateUserFn): AuthenticationResult {
    if (!pandaCookie) {
        return {
            success: false,
            reason: 'no-cookie'
        };
    }

    const parsedCookie = parseCookie(pandaCookie);
    if (!parsedCookie) {
        return {
            success: false,
            reason: 'invalid-cookie'
        };
    }
    const { data, signature } = parsedCookie;

    if (!verifySignature(data, signature, publicKey)) {
        return {
            success: false,
            reason: 'invalid-cookie'
        };
    }

    const currentTimestampInMillis = currentTime.getTime();

    try {
        const user: User = parseUser(data);
        const isExpired = user.expires < currentTimestampInMillis;

        if (isExpired) {
            const gracePeriodEndsAtEpochTimeMillis = user.expires + gracePeriodInMillis;
            if (gracePeriodEndsAtEpochTimeMillis < currentTimestampInMillis) {
                return {
                    success: false,
                    reason: 'expired-cookie'
                };
            } else {
                return {
                    success: true,
                    shouldRefreshCredentials: true,
                    mustRefreshByEpochTimeMillis: gracePeriodEndsAtEpochTimeMillis,
                    user
                }
            }
        }

        if (!validateUser(user)) {
            return {
                success: false,
                reason: 'invalid-user',
                user
            };
        }

        return {
            success: true,
            shouldRefreshCredentials: false,
            user
        };
    } catch (error) {
        console.error(error);
        return {
            success: false,
            reason: 'unknown'
        };
    }
}

export class PanDomainAuthentication {
    cookieName: string;
    region: string;
    bucket: string;
    keyFile: string;
    validateUser: ValidateUserFn;

    publicKey: Promise<PublicKeyHolder>;
    keyCacheTimeInMillis: number = 60 * 1000; // 1 minute
    keyUpdateTimer?: NodeJS.Timeout;
    s3Client: S3;

    constructor(cookieName: string, region: string, bucket: string, keyFile: string, validateUser: ValidateUserFn, credentialsProvider: AwsCredentialIdentityProvider = fromNodeProviderChain()) {
        this.cookieName = cookieName;
        this.region = region;
        this.bucket = bucket;
        this.keyFile = keyFile;
        this.validateUser = validateUser;

        const standardAwsConfig = {
            region: region,
            credentials: credentialsProvider,
        }; 
        this.s3Client = new S3(standardAwsConfig);
        this.publicKey = fetchPublicKey(this.s3Client, bucket, keyFile);

        this.keyUpdateTimer = setInterval(() => this.getPublicKey(), this.keyCacheTimeInMillis);
    }

    stop(): void {
        if(this.keyUpdateTimer) {
            clearInterval(this.keyUpdateTimer);
            this.keyUpdateTimer = undefined;
        }
    }

    getPublicKey(): Promise<string> {
        return this.publicKey.then(({ key, lastUpdated }) => {
            const now = new Date();
            const diff = now.getTime() - lastUpdated.getTime();

            if(diff > this.keyCacheTimeInMillis) {
                this.publicKey = fetchPublicKey(this.s3Client, this.bucket, this.keyFile);
                return this.publicKey.then(({ key }) => key);
            } else {
                return key;
            }
        });
    }

    verify(requestCookies: string | undefined): Promise<AuthenticationResult> {
        return this.getPublicKey().then(publicKey => {
            const cookies = cookie.parse(requestCookies ?? '');
            const pandaCookie = cookies[this.cookieName];
            return verifyUser(pandaCookie, publicKey, new Date(), this.validateUser);
        });
    }
}
