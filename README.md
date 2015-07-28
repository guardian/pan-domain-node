# pan-domain-node
NodeJs implementation of pan-domain auth verification

## Installation

`npm install --save git://github.com/guardian/pan-domain-node.git`


## Usage

Setup:

```
// app.js

var PanDomainNode = require('pan-domain-node');

PanDomainNode.setLogLevel('info'); // Defaults to 'error'

PanDomainNode.setAwsBucketDetails('MY_AWS_BUCKET', 'KEY_TO_MY_AWS_PUBLIC_KEY'); // Defaults to local GU settings

```

As express.js / connect style middleware:

```
// index.js

var pandaAuthMiddleware = require('pan-domain-node').Middleware;

router.get('/', pandaAuthMiddleware, function (req, res, next) {
    var guardianUser = req.guUser;
});

```

Error handling (see (express.js docs)[http://expressjs.com/guide/error-handling.html]):

```
// app.js

var PANDA_AUTH_ERROR_MESSAGE = PanDomainNode.PandaAuthFailedErrorMessage; // 'panda-auth-failed'

app.use(function(err, req, res, next) {
    if (err === PANDA_AUTH_ERROR_MESSAGE) {
        // redirect to sign in
        res.status(401).send('Please sign in to a gutools.co.uk application.');
    } else {
        next(err);
    };
});
```
