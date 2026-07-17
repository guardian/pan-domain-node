---
"@guardian/pan-domain-node": major
---

Create async builder method to instantiate PanDomainAuthentication class

Before: `const panda = new PanDomainAuthentication(...)`

After: `const panda = await PanDomainAuthentication.builder(...)`

This is a breaking change in how the main class is instantiated, allowing for better control flow in the way we handle fetching and updating public keys.

After instantiation, the usage of the class is the same as before.
