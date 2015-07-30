var crypto = require('crypto');
var colors = require('colors');

var Utils = {
    TEXT_ENCODING: 'ascii',
    AUTH_FAILED_ERROR_MESSAGE: 'panda-auth-failed',
    logLevel: 'error',
    logLevels: ['error', 'info', 'debug'],
    settings: {
        cookieName: 'gutoolsAuth-assym'
    
    }
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

Utils.setLogLevel = function (requestedLogLevel) {
    if (Utils.logLevels.indexOf(requestedLogLevel) !== -1) {
        Utils.logLevel = requestedLogLevel;
    } else {
        console.error(requestedLogLevel, 'is not a valid log level. Use one of: ', Utils.logLevels.join(', '));
    }
};

Utils.log = function (level, message) {

    var cols = {
        'error': 'red',
        'info': 'magenta',
        'debug': 'white'
    }

    if (Utils.logLevels.indexOf(level) <= Utils.logLevels.indexOf(Utils.logLevel)) {
        Array.isArray(message) ? console[level].apply(null, message) : console[level](message[cols[level]]);
    }
};

Utils.setAwsBucket = function (domain) {
    if (domain) {
        Utils.log('info', 'setting domain ' + domain);
        Utils.settings.pandaPublicKey =  pandaPublicKey + ".settings.public",
        Utils.settings.pandaBucket = 'pan-domain-auth-settings'
    } else {
        Utils.log('error', 'Please provide an S3 target domain and key for the AWS key download');
    }
};

Utils.userIsExpired = function (user) {
    var now = new Date();
    return new Date(user.expires) < now;
};

Utils.userIsValid = function (user) {
    return (user.email.indexOf('guardian.co.uk') !== -1) && (!!user.multifactor === true);
}

module.exports = Utils;
