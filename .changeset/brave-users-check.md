---
"@guardian/pan-domain-node": patch
---

Always run the `validateUser` function, including for expired cookies within the grace period. Previously, a user rejected by `validateUser` could be authenticated with `shouldRefreshCredentials: true` once their cookie had expired.

Users who fail validation now receive an `invalid-user` result regardless of cookie expiry, including when the cookie is outside the grace period (previously `expired-cookie`).
