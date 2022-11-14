package io.openpixee.security;

/** The restrictions that could be applied to a command being run through this type. */
public enum SystemCommandRestrictions {
  PREVENT_COMMAND_CHAINING,
  PREVENT_COMMON_EXPLOIT_EXECUTABLES,
  PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES
}
