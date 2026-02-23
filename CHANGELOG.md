# @guardian/pan-domain-node

## 1.2.2

### Patch Changes

- 567436a: no-op release to test migration to NPM trusted publishing #2

## 1.2.1

### Patch Changes

- 502bbd5: no-op release to test migration to NPM trusted publishing

## 1.2.0

### Minor Changes

- 5c14027: Fix app crash with no cookie value

## 1.1.0

### Minor Changes

- b762261: Download public key from S3 with AWS credential

## 1.0.0

### Major Changes

- f91598a: # Changes
  Adds a 24-hour grace period after cookie expiry, during which requests will still be considered authenticated.

  This is modelled by changing `AuthenticatedStatus` into a discriminated union with the following properties (among others):

  ### `success`

  Whether to treat request as authenticated or not. **This will remain true after cookie expiry for the length of the grace period.**

  [Almost all consumers](https://docs.google.com/spreadsheets/d/19XABaP9ua935TYJARkL8tstnizL69gIJ9av8C3UQBYw/edit?gid=0#gid=0) of this library check **only** the `AUTHORISED` status right now. These should all be able to switch to checking just this single boolean, implicitly getting grace period functionality in the process.

  ### `shouldRefreshCredentials`

  Whether to try and get fresh credentials.

  This allows page endpoints to redirect to auth, and API endpoints to tell the frontend to show a warning message to the user.

  ### `mustRefreshByEpochTimeMillis`

  The time at which the grace period ends and the request will be treated as unauthenticated. This allows library consumers to warn the user in the app UI when they are near the end of the grace period, as Composer does: https://github.com/guardian/flexible-content/pull/5210

  ```
  Panda cookie:               issued     expires                       `mustRefreshByEpochTimeMillis`
                              |          |                             |
                              |--1 hour--|                             |
  Grace period:                          [------------- 24 hours ------]

  `success`:         --false-][-true-----------------------------------][-false-------->
  `shouldRefreshCredentials`  [-false---][-true------------------------]
  ```

  # Why have we made this change?

  The Panda authentication cookie expires after 1 hour, and top-level navigation requests (page loads) trigger automatic re-authentication after this point.

  Unfortunately API requests cannot trigger re-authentication on their own, and background refresh mechanisms (e.g. iframe-based method used by [Pandular](https://github.com/guardian/pandular)) are increasingly blocked by browsers due to third-party cookie restrictions.

  We would like to enforce a 24-hour grace period

  # How to update consuming code

  At a minimum, switch from

  ```typescript
  const authResult = await panda.verify(cookieHeader);
  if (
    authResult.status === AuthenticationStatus.AUTHORISED &&
    authResult.user
  ) {
    return authResult.user.email;
  }
  ```

  to

  ```typescript
  const authResult = await panda.verify(cookieHeader);
  if (authResult.success) {
    return authResult.user.email;
  }
  ```

  This will implicitly give you grace period functionality, because `success` will remain true during the grace period.

  However, we **strongly** recommend all consumers to take account of `shouldRefreshCredentials`. What you do with the result should depend on whether your endpoint can trigger re-auth.

  ## Endpoints that can refresh credentials

  Endpoints that **can** refresh credentials, e.g. page endpoints that can redirect to an auth flow, should send the user to re-auth if `shouldRefreshCredentials` is `true`:

  ```typescript
  const authResult = await panda.verify(headers.cookie);
  if (authResult.success) {
    if (authResult.shouldRefreshCredentials) {
      // Send for auth
    } else {
      // Can perform action with user
      return authResult.user;
    }
  }
  ```

  ## Endpoints that cannot refresh credentials

  Endpoints that **cannot** refresh credentials, e.g. API endpoints, should log appropriately and return something to the client that can be used to warn the user that they need to refresh their session.

  ```typescript
  const authResult = await panda.verify(headers.cookie);
  if (authResult.success) {
    const user = authResult.user;
    // Handle request
    // When returning response:
    if (authResult.shouldRefreshCredentials) {
      const mustRefreshByEpochTimeMillis =
        authResult.mustRefreshByEpochTimeMillis;
      const remainingTime = mustRefreshByEpochTimeMillis - Date.now();
      console.warn(
        `Stale Panda auth, will expire in ${remainingTime} milliseconds`
      );
      // Can still return 200, but depending on the type of API,
      // we may want to return some extra information so the client
      // can warn the user they need to refresh their session.
    } else {
      // It's a fresh session. Nothing to worry about!
    }
  }
  ```

## 0.5.1

### Patch Changes

- bdd4adb: Testing changeset release and capitalising some text

## 0.5.0

### Minor Changes

- 01ddac5: Fix bug preventing cookie expiry from being correctly validated
