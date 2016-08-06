import createLogger from './logs';
import createKey from './key';
import pandaValidate from 'pan-domain-validate-user';

const AUTH_FAILED_ERROR_MESSAGE = 'panda-auth-failed';
const COOKIE_NAME = 'gutoolsAuth-assym';

export default function(config, overrideHttps, validate = pandaValidate) {
    // For backward compatibility, config can be the domain string or an object
    if (typeof config === 'string') {
        config = { domain: config };
    }
    const {
        domain,
        refresh = 10 * 60 * 1000, // 10 minutes
        logLevel = 'error',
        logger
    } = config;

    const log = createLogger(logger, logLevel);
    const key = createKey(domain, refresh, overrideHttps);

    function middleware (req, res, next) {
        key().then(pemKey => {
            const cookie = req.cookies[COOKIE_NAME];

            if (cookie) {
                validate(cookie, pemKey)
                .then(user => {
                    log('info', 'Panda Auth: User verified');
                    req.guUser = user;
                    next();
                })
                .catch(error => {
                    log('info', 'Panda Auth: ' + error.message);
                    next(AUTH_FAILED_ERROR_MESSAGE);
                });
            } else {
                log('info', 'Panda Auth: No cookie detected for "' + COOKIE_NAME + '"');
                next(AUTH_FAILED_ERROR_MESSAGE);
            }
        })
        .catch(ex => {
            log('error', 'Panda Auth: Could not verify cookie (perhaps couldn\'t reach AWS S3...)', ex);
            next(AUTH_FAILED_ERROR_MESSAGE);
        });
    }

    return {
        Middleware: middleware,
        setLogLevel: log.setLogLevel,
        setLogger: log.setLogger,
        PandaAuthFailedErrorMessage: AUTH_FAILED_ERROR_MESSAGE
    };
}
