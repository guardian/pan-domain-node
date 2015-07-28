var Q = require('q');
var Qs = require('qs');

var PandaUtils = require('./pandaUtils');
var PandaS3 = require('./pandaS3');

var AUTH_FAILED_ERROR_MESSAGE = 'panda-auth-failed';

var pandaAuthVerify = (function () {

    var pandaPublicKey;

    PandaS3.getKey().then(function (key) {
        pandaPublicKey = key;
    }, function (err) {
        pandaPublicKey = err; // TODO: Better fail state here
    });

    return function (req, res, next) {

        var guAuthCookie = req.cookies['gutoolsAuth-assym'],
            data,
            signature;

        if (!guAuthCookie) {
            res.status(401).end();
        } else if (pandaPublicKey) {

            var parsedCookie = PandaUtils.parseCookie(guAuthCookie);

            data = PandaUtils.decodeBase64(parsedCookie.data);
            signature = parsedCookie.signature;

            if (PandaUtils.verifySignature(data, signature, pandaPublicKey)) {

                PandaUtils.log('info', 'Panda Auth: User verified');
                req.guUser = Qs.parse(data);
                next();
            } else {

                PandaUtils.log('info', 'Panda Auth: User failed verification');
                next(AUTH_FAILED_ERROR_MESSAGE); // Cause request to fall through to error handler
            }

        } else {
            next(AUTH_FAILED_ERROR_MESSAGE); // Fall through response
        }
    }

})();

module.exports = {
    Middleware: pandaAuthVerify,
    setLogLevel: PandaUtils.setLogLevel,
    PandaAuthFailedErrorMessage: AUTH_FAILED_ERROR_MESSAGE
};
