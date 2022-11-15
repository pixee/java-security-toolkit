package io.openpixee.security;

/** The restrictions that could be applied to a command being run through this type. */
public enum SystemCommandRestrictions {
  /** Prevent multiple commands from being executed in a single call. */
  PREVENT_COMMAND_CHAINING,

  /**
   * Prevent commands commonly used in exploitation from being executed in a call (e.g., wget,
   * netcat)
   */
  PREVENT_COMMON_EXPLOIT_EXECUTABLES,

  /** Prevent commands from passing arguments that seem to be sensitive files (e.g., /etc/shadow) */
  PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES
}
