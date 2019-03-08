"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = __importStar(require("crypto"));
const https = __importStar(require("https"));
function decodeBase64(data) {
    return (new Buffer(data, 'base64')).toString('utf8');
}
exports.decodeBase64 = decodeBase64;
/**
 * Parse a pan-domain user cookie in to data and signature
 */
function parseCookie(cookie) {
    const splitCookie = cookie.split('\.');
    return {
        data: splitCookie[0],
        signature: splitCookie[1]
    };
}
exports.parseCookie = parseCookie;
/**
 * Verify signed data using nodeJs crypto library
 */
function verifySignature(message, signature, pandaPublicKey) {
    return crypto.createVerify('sha256WithRSAEncryption')
        .update(message, 'utf8')
        .verify(pandaPublicKey, signature, 'base64');
}
exports.verifySignature = verifySignature;
const ASCII_NEW_LINE = String.fromCharCode(10);
const PEM_HEADER = '-----BEGIN PUBLIC KEY-----';
const PEM_FOOTER = '-----END PUBLIC KEY-----';
function base64ToPEM(key) {
    const tmp = [];
    const ret = [new Buffer(PEM_HEADER).toString('ascii')];
    for (let i = 0, len = key.length; i < len; i++) {
        if (i > 0 && i % 64 === 0) {
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
exports.base64ToPEM = base64ToPEM;
function httpGet(path) {
    return new Promise((resolve, reject) => {
        const data = [];
        https.get(path, res => {
            res.on('data', chunk => data.push(chunk.toString('utf8')));
            res.on('error', err => reject(err));
            res.on('end', () => {
                const body = data.join('');
                if (res.statusCode == 200) {
                    resolve();
                }
                else {
                    // Response might be XML
                    const match = body.match(/<message>(.*)<\/message>/i);
                    const error = new Error(match ? match[1] : 'Invalid public key response');
                    reject(error);
                }
            });
        });
    });
}
exports.httpGet = httpGet;
