var crypto = require('crypto');

var Utils = {
    TEXT_ENCODING: 'ascii'
};

Utils.decodeBase64 = function (data) {
    return (new Buffer(data, 'base64')).toString('utf8')
}

/**
 * Parse a pan-domain user cookie in to data and signature
 */
Utils.parseCookie = function (cookie) {
    var splitCookie = cookie.split("\.");
    return {
        data: splitCookie[0],
        signature: splitCookie[1]
    };
};

/**
 * Algorithm that converts a single line base64 key strong to the expected
 * 64 char line break PEM format with header and footer
 */
Utils._formatKeyWithHeaders = function (PEM_HEADER, PEM_FOOTER, DATA) {

    var ASCII_NEW_LINE = String.fromCharCode(10), // \n
        tmp = [];

    var ret = [new Buffer(PEM_HEADER).toString(Utils.TEXT_ENCODING)];

    for (var i = 0; i < DATA.length; i++) {

        if (i>0 && i%64 === 0) {
            ret.push(tmp.join(''));
            tmp.length = 0;
        }

        tmp.push(DATA[i]);

        if (i === DATA.length - 1) {
            ret.push(tmp.join(''));
        }
    }

    ret.push(new Buffer(PEM_FOOTER).toString(Utils.TEXT_ENCODING));

    return ret.join(ASCII_NEW_LINE);
};

Utils.stringToRSAPublicFormat = function (string) {
    return Utils._formatKeyWithHeaders( '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', string);
};

/**
 * Verify signed data using nodeJs crypto library
 */
Utils.verifySignature = function (message, signature, pandaPublicKey) {
    return crypto.createVerify('sha256WithRSAEncryption')
                    .update(message)
                    .verify(pandaPublicKey, signature, 'base64');
};

module.exports = Utils;
