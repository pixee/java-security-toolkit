# Principles of API Design

## Securing and surfacing
Our APIs serve at least two different purposes. Some of our APIs offer comprehensive prevention of vulnerabilities, while others offer less assurance but fulfill another important need: to surface the security-relevant concerns of the call and alert the user to possible actions they can take to mitigate risk.

Consider an API being introduced like this:

```diff
-response.setHeader("X-Acme-Thing", possiblyTaintedValue);
+response.setHeader("X-Acme-Thing", Newlines.stripAll(possiblyTaintedValue));
```

This change will comprehensively protect against HTTP header injection.

Now consider a change meant to help protect against SSRF like this:

```diff
-URL u = new URL(possiblyTaintedValue);
+URL u = Urls.create(possiblyTaintedValue, Set.of(Urls.Protocol.HTTPS), HostValidator.ALLOW_ALL);
```

This change definitively reduces the risk of abuse by limiting the protocols attackers can use in a malicious URL value. Arguably just as important, the change also forces the developer to acknowledge that limiting the host in the URL could help even more. Unfortunately, an automated tool couldn't tell the tool what the host limitations *should be*, but even this subtle change makes developers aware of the non-obvious security requirement that should be considered.

## Type and method names
The type names and methods we offer should maintain a good balance of being as obvious as possible about how security is being provided while not being so esoteric that they won't be understood by developers who aren't familiar with the vulnerability in question.

There doesn't seem any practical way to measure this balance. We should just ensure a good-faith discussion between contributor and reviewer consider this on every change.

Examples of APIs we want to avoid:
* `SafeIO#safeReadLine(reader, 5000000)`. This API may be safe, it's not clear _why_ our change is making it safe and thus the developer may have less trust in it. It's also a bit risky because there may be future attacks against which this API doesn't protect, and this may be misleading.
* `Deserialization#createPubliclyKnownGadgetFilter()`. This API will help with deserialization attacks but unless the developer is intimately aware of how deserialization exploits work, this API looks like undecipherable nonsense. Given that, it seems we must balance the name of the API towards something that is slightly less specific.

# Code Quality

All code must be thoroughly tested.

New methods that solve problems involving specific libraries (e.g., Jackson) should be delivered in their own `java-security-toolkit-$LIBRARY` artifact. We already have an example of this with the [XStream security toolkit](https://github.com/pixee/java-security-toolkit-xstream), which helps secure [XStream library](https://x-stream.github.io/) usage. We want to do this so this library can require minimal dependencies so it continues to be easy to integrate, and the attack surface stays small. If you have ideas or proposals for APIs from other libraries to protect, please open an issue!
