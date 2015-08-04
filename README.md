# pan-domain-node
NodeJs implementation of pan-domain auth verification

## Installation

`npm install --save git://github.com/guardian/pan-domain-node.git`


## Usage

Setup:

```JavaScript
// app.js

var PanDomainNode = new require('pan-domain-node')('MY_APPLICATION_DOMAIN');

PanDomainNode.setLogLevel('info'); // Defaults to 'error'

```

As [express.js](http://expressjs.com/) / connect style middleware:

```JavaScript
// index.js

var pandaAuthMiddleware = require('pan-domain-node').Middleware;

router.get('/', pandaAuthMiddleware, function (req, res, next) {
    var guardianUser = req.guUser;

    // Do stuff with a verified user logged in
});

```

Error handling (see [express.js docs](http://expressjs.com/guide/error-handling.html)):

```JavaScript
// app.js

var PANDA_AUTH_ERROR_MESSAGE = PanDomainNode.PandaAuthFailedErrorMessage;

app.use(function(err, req, res, next) {
    if (err === PANDA_AUTH_ERROR_MESSAGE) {
        // redirect to sign in
        res.status(401).send('Please sign in to a gutools.co.uk application.');
    } else {
        next(err);
    };
});
```
