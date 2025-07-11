# Pan Domain Node 

Pan domain authentication provides distributed authentication for multiple webapps running in the same domain. Each
application can authenticate users against an OAuth provider and store the authentication information in a common cookie.
Each application can read this cookie and check if the user is allowed in the specific application and allow access accordingly.

This means that users are only prompted to provide authentication credentials once across the domain and any inter-app
interactions (e.g javascript Cross-Origin requests) can be easily secured.

## What's provided

The main [pan-domain-authentication](https://github.com/guardian/pan-domain-authentication) repository provides the
functionality for signing and verifying login cookies in Scala.

The `pan-domain-node` library provides an implementation of *verification only* for node apps.

## Grace period
We continue to consider the request authenticated for a period of time after the cookie expiry.

This is to allow API requests which cannot directly send the user for re-auth to indicate to the user that they must take some action to refresh their credentials (usually, refreshing the page).

When the cookie is expired but we're still within this grace period, `shouldRefreshCredentials` will be `true`, which means:
- Endpoints that can refresh credentials (e.g. page endpoints that can redirect) should do so
- Endpoints that cannot refresh credentials (e.g. API endpoints) should tell the user to take some action to refresh credentials

```
Panda cookie:               issued     expires                       `mustRefreshByEpochTimeMillis`
                            |          |                             |
                            |--1 hour--|                             |
Grace period:                          [------------- 24 hours ------]

`success`:         --false-][-true-----------------------------------][-false-------->
`shouldRefreshCredentials`  [-false---][-true------------------------]
```

## Example usage
### Installation
[![npm version](https://badge.fury.io/js/%40guardian%2Fpan-domain-node.svg)](https://badge.fury.io/js/%40guardian%2Fpan-domain-node)
```
npm install --save-dev @guardian/pan-domain-node
```

### Setup
The library requires AWS credential to read the public key files from the S3 bucket `pan-domain-auth-settings` in `Workflow` account.  Please ensure that the execution environment has AWS credential for an IAM profile that has read access to the bucket.

Currently, the bucket has been configured to allow access from any IAM users under a (fairly broad) list of AWS accounts (such as composer, cms-fronts, mobile etc).  Please get in touch with Workflow and Collaboration team if you need to get the read permission on the `pan-domain-auth-settings` bucket for your AWS acount.

### Initialisation
```typescript
import { PanDomainAuthentication, AuthenticationStatus, User, guardianValidation } from '@guardian/pan-domain-node';

const isRunningLocally = false;  // true if it runs locally.  False if it runs in AWS service such as EC2 and Lambda.

const panda = new PanDomainAuthentication(
  "gutoolsAuth-assym", // cookie name
  "eu-west-1", // AWS region
  "pan-domain-auth-settings", // Settings bucket
  "local.dev-gutools.co.uk.settings.public", // Settings file
  guardianValidation,
  isRunningLocally,
);

// alternatively customise the validation function and pass at construction
function customValidation(user: User): boolean {
  const isInCorrectDomain = user.email.indexOf('test.com') !== -1;
  return isInCorrectDomain && user.multifactor;
}
```

### Verification: page endpoints
This is for endpoints that **can** refresh credentials, e.g. a page endpoint that can redirect to an auth flow:
```typescript
const authenticationResult = await panda.verify(headers.cookie);
if (authenticationResult.success) {
    if (authenticationResult.shouldRefreshCredentials) {
        // Send for auth
    } else {
        // Can perform action with user
        return authenticationResult.user;
    }
}
```

### Verification: API endpoints
This is for endpoints that **cannot** refresh credentials, e.g. API endpoints:
```typescript
const authenticationResult = await panda.verify(headers.cookie);
if (authenticationResult.success) {
  const user = authenticationResult.user;
  // Handle request
  // When returning response:
  if (authenticationResult.shouldRefreshCredentials) {
    const mustRefreshByEpochTimeMillis = authenticationResult.mustRefreshByEpochTimeMillis;
    const remainingTime = mustRefreshByEpochTimeMillis - Date.now();
    console.warn(`Stale Panda auth, will expire in ${remainingTime} milliseconds`);
    // Can still return 200, but depending on the type of API,
    // we may want to return some extra information so the client
    // can warn the user they need to refresh their session.
   } else {
    // It's a fresh session. Nothing to worry about!
  }
}
```