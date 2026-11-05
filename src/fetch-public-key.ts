import { S3 } from "@aws-sdk/client-s3";
import * as ini from "ini";
import { toKeyObject } from "./utils";
import { KeyObject } from "crypto";

export interface PublicKeyHolder {
  keys: KeyObject[];
  lastUpdated: Date;
}

export function fetchPublicKey({
  s3,
  bucket,
  keyFile,
}: {
  s3: S3;
  bucket: string;
  keyFile: string;
}): Promise<PublicKeyHolder> {
  const publicKeyLocation = {
    Bucket: bucket,
    Key: keyFile,
  };

  return s3
    .getObject(publicKeyLocation)
    .then(({ Body }) => Body?.transformToString())
    .then((maybePandaConfigIni) => {
      if (!maybePandaConfigIni) {
        throw Error(
          `could not read panda config ${JSON.stringify(publicKeyLocation)}`,
        );
      }
      return parseKeysFromIni(maybePandaConfigIni);
    })
    .catch((error) => {
      console.error(`Error fetching public key from S3: ${error}`);
      throw error;
    });
}

// example: alsoAccept.0.publicKey
const isAlsoAcceptedKey = (key: string): boolean =>
  key.startsWith("alsoAccept.") && key.endsWith(".publicKey");

export function parseKeysFromIni(pandaConfigIni: string): PublicKeyHolder {
  const config = ini.parse(pandaConfigIni);
  const maybePublicKey = config.publicKey;
  if (!maybePublicKey) {
    console.log(
      `Failed to retrieve panda public key from ${JSON.stringify(config)}`,
    );
    throw new Error("Missing publicKey setting from config");
  }

  const alsoAcceptedKeys: KeyObject[] = Object.entries(config)
    .filter(([key, _value]) => isAlsoAcceptedKey(key))
    .map(([_key, value]) => toKeyObject(value));

  return {
    keys: [toKeyObject(config.publicKey), ...alsoAcceptedKeys],
    lastUpdated: new Date(),
  };
}
