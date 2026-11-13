import * as crypto from "crypto";

export function decodeBase64(data: string): string {
  return Buffer.from(data, "base64").toString("utf8");
}

export type ParsedCookie = { data: string; signature: string };

export class CookiePayload {
  constructor(public data: string, public signature: string) {}

  payloadTextVerifiedSignedWith(
    publicKey: crypto.KeyObject,
  ): string | undefined {
    try {
      const isValid = crypto
        .createVerify("sha256WithRSAEncryption")
        .update(this.data, "utf8")
        .verify(publicKey, this.signature, "base64");

      if (isValid) {
        return this.data;
      } else {
        return undefined;
      }
    } catch (_err) {
      console.error("Error verifying signature");
      return undefined;
    }
  }

  /**
   * Parse a pan-domain user cookie in to data and signature
   * Validates that the cookie is properly formatted (two base64 strings separated by '.')
   */
  static fromCookieText(cookie: string): CookiePayload | undefined {
    const cookieRegex = /^([\w\W]*)\.([\w\W]*)$/;
    const match = cookie.match(cookieRegex);

    if (!match) {
      return undefined;
    }

    const [, data, signature] = match;

    if (!isBase64(data) || !isBase64(signature)) {
      return undefined;
    }

    return new CookiePayload(decodeBase64(data), signature);
  }
}

/**
 * Check if a string is valid base64
 */
function isBase64(str: string): boolean {
  try {
    return Buffer.from(str, "base64").toString("base64") === str;
  } catch (err) {
    return false;
  }
}
