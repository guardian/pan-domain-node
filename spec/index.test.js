import test from 'ava';
import createPanda from '../lib/index';
import EventEmitter from 'events';

test.cb('validation fails if the key is not available', t => {
    t.plan(3);

    const https = mockHttpsFail();

    const panda = createPanda('CODE', https);
    panda.setLogger((level, message) => {
        t.regex(message, /verify/i);
    });
    panda.Middleware({}, {}, (error) => {
        t.truthy(error);
        t.is(error, panda.PandaAuthFailedErrorMessage);
        t.end();
    });
});

test.cb('validation fails if the cookie is missing', t => {
    t.plan(3);

    const https = mockHttpsSuccess();
    const req = { cookies: {} };

    const panda = createPanda({
        domain: 'CODE',
        logger (level, message) {
            t.regex(message, /cookie/i);
        },
        logLevel: 'info'
    }, https);
    panda.Middleware(req, {}, (error) => {
        t.truthy(error);
        t.is(error, panda.PandaAuthFailedErrorMessage);
        t.end();
    });
});

test.cb('validation fails when decoding the cookie', t => {
    t.plan(4);

    const https = mockHttpsSuccess();
    const req = { cookies: { 'gutoolsAuth-assym': 'hello'} };
    const validate = (cookie) => {
        t.is(cookie, 'hello');
        return Promise.reject(new Error('expired token'));
    };

    const panda = createPanda({
        domain: 'CODE',
        logger (level, message) {
            t.regex(message, /expired/i);
        },
        logLevel: 'info'
    }, https, validate);
    panda.Middleware(req, {}, (error) => {
        t.truthy(error);
        t.is(error, panda.PandaAuthFailedErrorMessage);
        t.end();
    });
});

test.cb('validation successful sets the user on the request', t => {
    t.plan(3);

    const https = mockHttpsSuccess();
    const req = { cookies: { 'gutoolsAuth-assym': 'hello'} };
    const validate = () => Promise.resolve({ email: 'nice-person' });

    const panda = createPanda({
        domain: 'CODE',
        logger (level, message) {
            t.regex(message, /verified/i);
        },
        logLevel: 'info'
    }, https, validate);
    panda.Middleware(req, {}, (error) => {
        t.falsy(error);
        t.deepEqual(req.guUser, { email: 'nice-person' });
        t.end();
    });
});

class EmitterError extends EventEmitter {
	constructor () {
		super();
		process.nextTick(() => this.emit('error', 'emitting an error'));
	}
}
class EmitterResponse extends EventEmitter {
	constructor (key) {
		super();
		this.statusCode = 200;
		process.nextTick(() => {
			this.emit('data', 'publicKey=' + key);
			this.emit('end');
		});
	}
}

function mockHttpsSuccess () {
    return {
        get (path, cb) {
            cb(new EmitterResponse('abc'));
        }
    };
}

function mockHttpsFail () {
    return {
        get (path, cb) {
            cb(new EmitterError());
        }
    };
}
