package io.openpixee.security;

/**
 * The set of restrictions developers can use when using {@link Reflection} APIs.
 *
 * @see Reflection
 */
public enum ReflectionRestrictions {
  MUST_BE_PUBLIC,
  MUST_NOT_INVOLVE_CODE_EXECUTION
}
