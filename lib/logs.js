const LOG_LEVELS = ['error', 'info', 'debug'];

export default function(logger, thresholdLevel = 'error') {
    const logFunction = function(level, ...messages) {
        if (LOG_LEVELS.indexOf(level) <= LOG_LEVELS.indexOf(thresholdLevel)) {
            if (logger) {
                logger(level, ...messages);
            } else {
                // eslint-disable-next-line no-console
                console[level](...messages);
            }
        }
    };

    logFunction.setLogLevel = function(newLevel) {
        thresholdLevel = newLevel;
    };

    logFunction.setLogger = function(newLogger) {
        logger = newLogger;
    };

    return logFunction;
}
