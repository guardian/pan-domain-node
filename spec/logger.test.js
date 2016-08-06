import test from 'ava';
import createLogger from '../lib/logs';

test('logger sends messages of the same log level', t => {
    t.plan(2);

    const logger = createLogger((level, message) => {
        t.is(level, 'error');
        t.is(message, 'hello');
    });
    logger('error', 'hello');
});

test('logger ignore messages with a lower level', t => {
    t.plan(0);

    const logger = createLogger(() => {
        t.fail('message should not be logged');
    });
    logger('debug', 'hello');
});

test('logger allows to change logger and level', t => {
    t.plan(3);

    const logger = createLogger(() => {
        t.fail('original logger should not be called');
    });
    logger.setLogLevel('debug');
    logger.setLogger((level, one, two) => {
        t.is(level, 'debug');
        t.is(one, 'one');
        t.is(two, 'two');
    });

    logger('debug', 'one', 'two');
});
