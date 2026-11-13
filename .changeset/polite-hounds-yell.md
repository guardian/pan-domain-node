---
"@guardian/pan-domain-node": major
---

Support multiple public keys when verifying cookies.

Alongside `publicKey`, any `alsoAccept.<n>.publicKey` entries in the settings file are now also accepted. A cookie is valid if its signature verifies against any of these keys, which allows keys to be rotated without downtime. Key additions and removals are logged by key hash when the config is refreshed.

Also adds a `decode` method, following the Scala library, which runs a callback against each public key in turn until one succeeds.

Breaking changes:

- `getPublicKey(): Promise<string>` has been replaced by `getPublicKeys(): Promise<KeyObject[]>`.
- `PublicKeyHolder` (the type of the `publicKey` property) now has `keys: KeyObject[]` instead of `key: string`.
- `verifyUser` in `panda.ts` has been replaced by `validateVerifiedPayload`, which takes already-verified cookie data.
