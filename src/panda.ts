import * as cookie from "cookie";
import * as crypto from "crypto";

import { S3 } from "@aws-sdk/client-s3";
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import {
  AuthenticationResult,
  gracePeriodInMillis,
  User,
  ValidateUserFn,
} from "./api";
import { fetchPublicKey, PublicKeyHolder } from "./fetch-public-key";
import { getErrorMessage } from "./getErrorMessage";
import {
  calculateKeyObjectHashId,
  logKeyDiffs,
  parseUser,
  sign,
} from "./utils";
import { CookiePayload } from "./cookiePayload";

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

  const queryParamsString = Buffer.from(combined).toString("base64");

  const signature = sign(combined, privateKey);

  return queryParamsString + "." + signature;
}

export function verifyUser(
  pandaCookieData: string,
  currentTime: Date,
  validateUser: ValidateUserFn,
): AuthenticationResult {
  const currentTimestampInMillis = currentTime.getTime();

  try {
    const user: User = parseUser(pandaCookieData);
    const isExpired = user.expires < currentTimestampInMillis;

    if (!validateUser(user)) {
      return {
        success: false,
        reason: "invalid-user",
        user,
      };
    }

    if (isExpired) {
      const gracePeriodEndsAtEpochTimeMillis =
        user.expires + gracePeriodInMillis;
      if (gracePeriodEndsAtEpochTimeMillis < currentTimestampInMillis) {
        return {
          success: false,
          reason: "expired-cookie",
        };
      } else {
        return {
          success: true,
          shouldRefreshCredentials: true,
          mustRefreshByEpochTimeMillis: gracePeriodEndsAtEpochTimeMillis,
          user,
        };
      }
    }

    return {
      success: true,
      shouldRefreshCredentials: false,
      user,
    };
  } catch (error) {
    console.error(error);
    return {
      success: false,
      reason: "unknown",
    };
  }
}

export type BuilderParams = {
  cookieName: string;
  region: string;
  bucket: string;
  keyFile: string;
  validateUser: ValidateUserFn;
  credentialsProvider?: AwsCredentialIdentityProvider;
};

export class PanDomainAuthentication {
  cookieName: string;
  bucket: string;
  keyFile: string;
  validateUser: ValidateUserFn;

  publicKey: PublicKeyHolder;
  keyCacheTimeInMillis: number = 60 * 1000; // 1 minute
  keyUpdateTimer?: NodeJS.Timeout;
  s3Client: S3;

  static async builder({
    cookieName,
    region,
    bucket,
    keyFile,
    validateUser,
    credentialsProvider = fromNodeProviderChain(),
  }: BuilderParams): Promise<PanDomainAuthentication> {
    const s3Client = new S3({
      region,
      credentials: credentialsProvider,
    });
    const publicKey = await fetchPublicKey({
      s3: s3Client,
      bucket,
      keyFile,
    });

    return new PanDomainAuthentication(
      cookieName,
      bucket,
      s3Client,
      keyFile,
      validateUser,
      publicKey,
    );
  }

  constructor(
    cookieName: string,
    bucket: string,
    s3Client: S3,
    keyFile: string,
    validateUser: ValidateUserFn,
    publicKey: PublicKeyHolder,
  ) {
    this.cookieName = cookieName;
    this.bucket = bucket;
    this.keyFile = keyFile;
    this.publicKey = publicKey;
    this.validateUser = validateUser;
    this.s3Client = s3Client;

    this.keyUpdateTimer = setInterval(
      () => this.getPublicKeys(),
      this.keyCacheTimeInMillis,
    );
  }

  stop(): void {
    if (this.keyUpdateTimer) {
      clearInterval(this.keyUpdateTimer);
      this.keyUpdateTimer = undefined;
      console.log("Stopped key update timer for PanDomainAuthentication");
    }
  }

  async getPublicKeys(): Promise<crypto.KeyObject[]> {
    const publicKeyHolder = this.publicKey;
    const now = new Date();
    const diff = now.getTime() - publicKeyHolder.lastUpdated.getTime();

    if (diff > this.keyCacheTimeInMillis) {
      try {
        const newKeyHolder = await fetchPublicKey({
          s3: this.s3Client,
          bucket: this.bucket,
          keyFile: this.keyFile,
        });
        const { keys } = newKeyHolder;
        this.publicKey = newKeyHolder;

        logKeyDiffs(publicKeyHolder.keys, keys);

        return keys;
      } catch (error) {
        console.error(
          `Error fetching public key from S3, falling back to cached key. Error: ${getErrorMessage(
            error,
          )}`,
        );
        return publicKeyHolder.keys;
      }
    } else {
      return publicKeyHolder.keys;
    }
  }

  async decode<T>(
    f: (publicKey: crypto.KeyObject) => T | undefined | Promise<T | undefined>,
  ): Promise<T | undefined> {
    const publicKeys = await this.getPublicKeys();
    for (const key of publicKeys) {
      try {
        const result = await f(key);
        if (result !== undefined) {
          console.log(
            `Successfully decoded with one of the public keys. Key hash: ${calculateKeyObjectHashId(
              key,
            )}`,
          );
          return result;
        }
      } catch (error) {
        console.error(
          `Error decoding with public key ${calculateKeyObjectHashId(
            key,
          )}: ${getErrorMessage(error)}`,
        );
      }
    }
    return undefined;
  }

  async verify(
    requestCookies: string | undefined,
  ): Promise<AuthenticationResult> {
    const cookies = cookie.parse(requestCookies ?? "");
    const pandaCookie = cookies[this.cookieName];
    if (!pandaCookie) {
      return {
        success: false,
        reason: "no-cookie",
      };
    }
    const cookiePayload = CookiePayload.fromCookieText(pandaCookie);
    if (cookiePayload === undefined) {
      return {
        success: false,
        reason: "invalid-cookie",
      };
    }
    const maybeVerifiedData = await this.decode((key) =>
      cookiePayload.payloadTextVerifiedSignedWith(key),
    );
    if (maybeVerifiedData === undefined) {
      return {
        success: false,
        reason: "invalid-cookie",
      };
    }
    return verifyUser(maybeVerifiedData, new Date(), this.validateUser);
  }
}
