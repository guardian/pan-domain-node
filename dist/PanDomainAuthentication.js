"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const iniparser = __importStar(require("iniparser"));
const cookie = __importStar(require("cookie"));
const qs = __importStar(require("qs"));
const utils_1 = require("./utils");
const api_1 = require("./api");
function fetchPublicKey(region, bucket, keyFile) {
    const path = `https://s3.${region}.amazonaws.com/${bucket}/${keyFile}`;
    return utils_1.httpGet(path).then(response => {
        const config = iniparser.parseString(response);
        if (config.publicKey) {
            return {
                key: utils_1.base64ToPEM(config.publicKey),
                lastUpdated: new Date()
            };
        }
        else {
            throw new Error("Missing publicKey setting from config");
        }
    });
}
function verifyUser(pandaCookie, publicKey, validateUser) {
    if (!pandaCookie) {
        return { status: api_1.AuthenticationStatus.INVALID_COOKIE };
    }
    const { data, signature } = utils_1.parseCookie(pandaCookie);
    if (!utils_1.verifySignature(data, signature, publicKey)) {
        return { status: api_1.AuthenticationStatus.INVALID_COOKIE };
    }
    const user = qs.parse(data);
    const now = new Date();
    const isExpired = new Date(user.expires) < now;
    if (isExpired) {
        return { status: api_1.AuthenticationStatus.EXPIRED, user };
    }
    if (!validateUser(user)) {
        return { status: api_1.AuthenticationStatus.NOT_AUTHORISED, user };
    }
    return { status: api_1.AuthenticationStatus.AUTHORISED, user };
}
class PanDomainAuthentication {
    constructor(cookieName, region, bucket, keyFile, validateUser) {
        this.keyCacheTime = 60 * 1000; // 1 minute
        this.cookieName = cookieName;
        this.region = region;
        this.bucket = bucket;
        this.keyFile = keyFile;
        this.validateUser = validateUser;
        this.publicKey = fetchPublicKey(region, bucket, keyFile);
    }
    getPublicKey() {
        return this.publicKey.then(({ key, lastUpdated }) => {
            const now = new Date();
            const diff = now.getMilliseconds() - lastUpdated.getMilliseconds();
            if (diff > this.keyCacheTime) {
                this.publicKey = fetchPublicKey(this.region, this.bucket, this.keyFile);
                return this.publicKey.then(({ key }) => key);
            }
            else {
                return key;
            }
        });
    }
    verify(requestCookies) {
        return this.getPublicKey().then(publicKey => {
            const cookies = cookie.parse(requestCookies);
            const pandaCookie = cookies[this.cookieName];
            return verifyUser(pandaCookie, publicKey, this.validateUser);
        });
    }
}
exports.PanDomainAuthentication = PanDomainAuthentication;
