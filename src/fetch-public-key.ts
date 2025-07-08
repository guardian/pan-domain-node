import * as iniparser from 'iniparser';
import {base64ToPEM, httpGet} from './utils';
import { S3 } from "@aws-sdk/client-s3";

export interface PublicKeyHolder {
    key: string,
    lastUpdated: Date
}


export function fetchPublicKey(s3: S3, region: string, bucket: string, keyFile: string): Promise<PublicKeyHolder> {

    const publicKeyLocation = {
        Bucket: bucket,
        Key: keyFile,
    };

    return s3.getObject(publicKeyLocation)
        .then(({ Body }) => Body?.transformToString())
        .then((pandaConfigIni) => {
            if (!pandaConfigIni) {
                throw Error(`could not read panda config ${JSON.stringify(publicKeyLocation)}`);
            }
            else {
                const config: { publicKey?: string } = iniparser.parseString(pandaConfigIni);
                if (config.publicKey) {
                    return {
                        key: base64ToPEM(config.publicKey, "PUBLIC"),
                        lastUpdated: new Date()
                    };
                } else {
                    console.log(`Failed to retrieve panda public key from ${JSON.stringify(config)}`);
                    throw new Error("Missing publicKey setting from config");
                }
            }
        });
}


