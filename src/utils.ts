import * as crypto from 'crypto';
import * as https from 'https';

export function decodeBase64(data: string): string {
    return (new Buffer(data, 'base64')).toString('utf8')
}

/**
 * Parse a pan-domain user cookie in to data and signature
 */
export function parseCookie(cookie: string): { data: string, signature: string} {
    const splitCookie = cookie.split('\.');
    return {
        data: splitCookie[0],
        signature: splitCookie[1]
    };
}

/**
 * Verify signed data using nodeJs crypto library
 */
export function verifySignature(message: string, signature: string, pandaPublicKey: string): boolean {
    return crypto.createVerify('sha256WithRSAEncryption')
        .update(message, 'utf8')
        .verify(pandaPublicKey, signature, 'base64');
}

const ASCII_NEW_LINE = String.fromCharCode(10);
const PEM_HEADER = '-----BEGIN PUBLIC KEY-----';
const PEM_FOOTER = '-----END PUBLIC KEY-----';

export function base64ToPEM (key: string): string {
	const tmp = [];

    const ret = [new Buffer(PEM_HEADER).toString('ascii')];

    for (let i = 0, len = key.length; i < len; i++) {

        if (i>0 && i%64 === 0) {
            ret.push(tmp.join(''));
            tmp.length = 0;
        }

        tmp.push(key[i]);

        if (i === key.length - 1) {
            ret.push(tmp.join(''));
        }
    }

    ret.push(new Buffer(PEM_FOOTER).toString('ascii'));

    return ret.join(ASCII_NEW_LINE);
}

export function httpGet(path: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const data: string[] = [];

        https.get(path, res => {
            res.on('data', chunk => data.push(chunk.toString('utf8')));
            res.on('error', err => reject(err));

            res.on('end', () => {
                const body = data.join(''); 

                if(res.statusCode == 200) {
                    resolve();
                } else {
                    // Response might be XML
					const match = body.match(/<message>(.*)<\/message>/i);
					const error = new Error(match ? match[1] : 'Invalid public key response');
                    
                    reject(error);
                }
            });
        });
    });
}