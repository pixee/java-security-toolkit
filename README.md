[![Actions Status](https://github.com/pixeeworks/java-security-toolkit/workflows/Java%20CI/badge.svg)](https://github.com/pixeeworks/java-security-toolkit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# Java Code Security Toolkit

This utility hosts a number of code security controls for various application security vulnerability categories. It can 
be used directly by programmers, but you may have been introduced to it by being having it directly added to you code by 
automation.

Many of the APIs provided are meant to be drop-in replacements that either offer more secure defaults, harden against common attacks, or at least surface the security questions developers should answer when using risky APIs. Here are a few examples:

### Example 1: Safely accessing URLs

Fetching [URLs](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/URL.html) is potentially unsafe because of the wide universe of hosts, protocols, and capabilities this may expose. We offer an API that makes it considerably higher assurance, allowing the developer to dictate their expectations about the result, causing a `SecurityException` to be thrown if they're not met:

```diff
-  URL u = new URL(str); // dangerous -- can be to ftp://evil.com/ for all we know
+  URL u = Urls.create(str, Set.of(UrlsProtocols.HTTPS), HostValidator.fromAllowedHostPattern(Pattern.compile("good\\.com"));
```

### Example 2: Hardening Java deserialization

Deserializing using [ObjectInputStream](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/ObjectInputStream.html) is [extremely dangerous](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#java) (here's a [from-zero-to-exploit talk](https://www.youtube.com/watch?v=kpuEtsGXKR8) we gave about it).  We offer an API to offer a strong, 1-line, zero-tradeoff protection against this attack.

```diff
   ObjectInputStream ois = ...;
+  ObjectInputFilters.enableObjectFilterIfUnprotected(ois); // now protected against all publicly known gadgets
   Acme acme = (Acme)ois.readObject();
```

## Adding to your project 

In Maven:
```xml
<dependency>
  <groupId>io.github.pixee</groupId>
  <artifactId>java-security-toolkit</artifactId>
  <version>1.1.2</version>
</dependency>
```
In Gradle:
```kotlin
implementation("io.github.pixee:java-security-toolkit:1.1.2")
```

## Contributing 
We'd love to get contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

### Building
Building is meant for Java 11:

```
./gradlew check
```

## FAQ

### How does this compare to OWASP ESAPI?

We actually contributed to OWASP ESAPI and other OWASP projects in the past and remain fans today! 

There is some limited overlap, but ESAPI is much more broad in its ambitions, and as a result is considerably more "heavyweight". It also is not focused on hardening or sandboxing solutions, instead preferring to offer concrete solutions for problems that require business context to implement. Our library also has very few dependencies, no configuration, and is generally designed to offer much less friction to "drop in" to a codebase.
