[![Actions Status](https://github.com/pixeeworks/java-security-toolkit/workflows/Java%20CI/badge.svg)](https://github.com/pixeeworks/java-security-toolkit/actions)
![Coverage](.github/badges/jacoco.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# Java Code Security Toolkit

This utility hosts a number of code security controls for various application security vulnerability categories. It can 
be used directly by programmers, but you may have been introduced to it by being having it directly added to you code by 
automation.

Many of the APIs provided are meant to be drop-in replacements that either offer more secure defaults, harden against common attacks, or at least surface the security questions developers should answer when using risky APIs.

## Building
Building is meant for Java 11 and Maven 3:

```
mvn clean package
```
