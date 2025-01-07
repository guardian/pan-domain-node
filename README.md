# Pan Domain Node 

Pan domain authentication provides distributed authentication for multiple webapps running in the same domain. Each
application can authenticate users against an OAuth provider and store the authentication information in a common cookie.
Each application can read this cookie and check if the user is allowed in the specific application and allow access accordingly.

This means that users are only prompted to provide authentication credentials once across the domain and any inter-app
interactions (e.g javascript cross-origin requests) can be easily secured.

## What's provided

The main [pan-domain-authentication](https://github.com/guardian/pan-domain-authentication) repository provides the
functionality for signing and verifying login cookies in Scala.

The `pan-domain-node` library provides an implementation of *verification only* for node apps.

## To verify login in NodeJS

[![npm version](https://badge.fury.io/js/%40guardian%2Fpan-domain-node.svg)](https://badge.fury.io/js/%40guardian%2Fpan-domain-node)

```
npm install --save-dev @guardian/pan-domain-node
```

```typescript
import { PanDomainAuthentication, AuthenticationStatus, User, guardianValidation } from '@guardian/pan-domain-node';

const panda = new PanDomainAuthentication(
  "gutoolsAuth-assym", // cookie name
  "eu-west-1", // AWS region
  "pan-domain-auth-settings", // Settings bucket
  "local.dev-gutools.co.uk.settings.public", // Settings file
  guardianValidation
);

// alternatively customise the validation function and pass at construction
function customValidation(user: User): boolean {
  const isInCorrectDomain = user.email.indexOf('test.com') !== -1;
  return isInCorrectDomain && user.multifactor;
}

// when handling a request
function(request) {
  // Pass the raw unparsed cookies
  return panda.verify(request.headers['Cookie']).then(( { status, user }) => {
    switch(status) {
      case AuthenticationStatus.Authorised:
        // Good user, handle the request!

      default:
        // Bad user. Return 4XX
    }
  });
}
```
