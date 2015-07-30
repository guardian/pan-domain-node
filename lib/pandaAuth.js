var Q = require('q');
var Qs = require('qs');

var PandaUtils = require('./pandaUtils');
var PandaS3 = require('./pandaS3');

var pandaAuthVerify = (function () {

    var pandaPublicKey;

    PandaS3.getKey().then(function (key) {
        pandaPublicKey = key;
    }, function (err) {
        pandaPublicKey = err; // TODO: Better fail state here
    });

    return function (req, res, next) {

        var guAuthCookie = req.cookies[PandaUtils.settings.cookieName],
            data,
            signature;

        if (!guAuthCookie) {
            PandaUtils.log('info', 'Panda Auth: No cookie detected for "' + PandaUtils.settings.cookieName + '"');
            next(PandaUtils.AUTH_FAILED_ERROR_MESSAGE);
        } else if (pandaPublicKey) {

            var parsedCookie = PandaUtils.parseCookie(guAuthCookie);

            data = PandaUtils.decodeBase64(parsedCookie.data);
            signature = parsedCookie.signature;

            if (PandaUtils.verifySignature(data, signature, pandaPublicKey)) {

                var user = Qs.parse(data);

                var isExpired = PandaUtils.userIsExpired(user);

                var isValid = PandaUtils.userIsValid(user);

                if (isExpired) {
                    PandaUtils.log('info', 'Panda Auth: Users authorisation has expired');
                    next(PandaUtils.AUTH_FAILED_ERROR_MESSAGE);
                } else if (!isValid) {
                    PandaUtils.log('info', 'Panda Auth: User is not a valid Guardian user or doesn\'t have 2FA turned on');
                    next(PandaUtils.AUTH_FAILED_ERROR_MESSAGE);
                } else {
                    PandaUtils.log('info', 'Panda Auth: User verified');
                    req.guUser = user;
                    next();
                }
            } else {

                PandaUtils.log('info', 'Panda Auth: User failed verification');
                next(PandaUtils.AUTH_FAILED_ERROR_MESSAGE); // Cause request to fall through to error handler
            }

        } else {
            PandaUtils.log('info', 'Panda Auth: Could not verify cookie (perhaps couldn\'t reach AWS S3...)');
            next(PandaUtils.AUTH_FAILED_ERROR_MESSAGE); // Fall through response
        }
    }
})();

module.exports = function (domain) {

    return {
        Middleware: pandaAuthVerify,
        setLogLevel: PandaUtils.setLogLevel,
        PandaAuthFailedErrorMessage: PandaUtils.AUTH_FAILED_ERROR_MESSAGE,
        setAwsBucketDetails: PandaUtils.setAwsBucket(domain)
    };
};
