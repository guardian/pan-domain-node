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
var overriddenLogger;

Utils.decodeBase64 = function (data) {
    return (new Buffer(data, 'base64')).toString('utf8')
}

/**
 * Parse a pan-domain user cookie in to data and signature
 */
Utils.parseCookie = function (cookie) {
    var splitCookie = cookie.split('\.');
    return {
        data: splitCookie[0],
        signature: splitCookie[1]
    };
};

/**
 * Verify signed data using nodeJs crypto library
 */
Utils.verifySignature = function (message, signature, pandaPublicKey) {
    return crypto.createVerify('sha256WithRSAEncryption')
                    .update(message, 'utf-8')
                    .verify(pandaPublicKey, signature, 'base64');
};

Utils.setLogger = function (logger) {
    overriddenLogger = logger;
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
        if (overriddenLogger) {
            overriddenLogger(level, message);
        } else {
            Array.isArray(message) ? console[level].apply(null, message) : console[level](message[cols[level]]);
        }
    }
};

Utils.setAwsBucket = function (domain) {
    if (domain) {
        Utils.log('info', 'setting domain ' + domain);
        Utils.settings.pandaPublicKey =  domain + '.settings.public';
        Utils.settings.pandaBucket = 'pan-domain-auth-settings';
        Utils.settings.domain = domain;
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
