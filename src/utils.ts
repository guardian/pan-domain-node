import * as crypto from "crypto";
import * as https from "https";

import { URLSearchParams } from "url";
import { User } from "./api";

export function sign(message: string, privateKey: string): string {
  const sign = crypto.createSign("sha256WithRSAEncryption");
  sign.write(message);
  sign.end();

  return sign.sign(privateKey, "base64");
}

export function toKeyObject(publicKeyString: string): crypto.KeyObject {
  return crypto.createPublicKey(
    `-----BEGIN PUBLIC KEY-----\n${publicKeyString}\n-----END PUBLIC KEY-----`,
  );
}

export function parseUser(data: string): User {
  const params = new URLSearchParams(data);

  function stringField(name: string): string {
    const value = params.get(name);
    if (!value) {
      throw new Error(`Missing ${name}`);
    }

    return value;
  }

  function numberField(name: string): number {
    const value = params.get(name);
    if (!value) {
      throw new Error(`Missing ${name}`);
    }

    return parseInt(value);
  }

  function booleanField(name: string): boolean {
    return params.get(name) === "true";
  }

  function stringListField(name: string): string[] {
    const value = params.get(name);
    if (!value) {
      throw new Error(`Missing ${name}`);
    }

    return value.split(",");
  }

  const avatarUrl = params.get("avatarUrl");

  return {
    firstName: stringField("firstName"),
    lastName: stringField("lastName"),
    email: stringField("email"),
    avatarUrl: avatarUrl ? avatarUrl : undefined,
    authenticatingSystem: stringField("system"),
    authenticatedIn: stringListField("authedIn"),
    expires: numberField("expires"),
    multifactor: booleanField("multifactor"),
  };
}

const NumberOfDigitsNecessaryToAvoidBirthdayCollisions: number = 5;

export function calculateKeyObjectHashId(key: crypto.KeyObject): string {
  const derBytes = key.export({ type: "spki", format: "der" });
  const hashBytes = crypto.createHash("sha256").update(derBytes).digest();

  const unsignedValue = BigInt("0x" + hashBytes.toString("hex"));
  const absValue =
    hashBytes[0] >= 0x80
      ? (BigInt(1) << BigInt(256)) - unsignedValue
      : unsignedValue;

  return absValue
    .toString(36)
    .slice(0, NumberOfDigitsNecessaryToAvoidBirthdayCollisions);
}

export function logKeyDiffs(
  oldKeys: crypto.KeyObject[],
  newKeys: crypto.KeyObject[],
): void {
  // Set.difference doesn't seem to be available yet :,(
  const addedKeys = newKeys.filter(
    (key) => !oldKeys.some((oldKey) => oldKey.equals(key)),
  );
  const removedKeys = oldKeys.filter(
    (key) => !newKeys.some((newKey) => newKey.equals(key)),
  );

  if (addedKeys.length > 0) {
    console.log(
      `New public keys added. Key hashes: ${[...addedKeys]
        .map(calculateKeyObjectHashId)
        .join(", ")}`,
    );
  }

  if (removedKeys.length > 0) {
    console.log(
      `Public keys removed. Key hashes: ${[...removedKeys]
        .map(calculateKeyObjectHashId)
        .join(", ")}`,
    );
  }
}
