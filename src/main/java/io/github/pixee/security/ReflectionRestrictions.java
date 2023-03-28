package io.github.pixee.security;

/**
 * The set of restrictions developers can use when using {@link Reflection} APIs.
 *
 * @see Reflection
 */
public enum ReflectionRestrictions {
  /** Enforces that a class must be public. */
  MUST_BE_PUBLIC,

  /** Enforces that a class must not be related to code execution. */
  MUST_NOT_INVOLVE_CODE_EXECUTION
}
