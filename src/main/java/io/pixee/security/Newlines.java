package io.pixee.security;

/** This type exposes helper methods that will help defend against newline-based attacks. */
public final class Newlines {

  private Newlines() {}

  /** Removes newlines from the given string, if any exist. */
  public static String stripAll(final String value) {
    if (value == null) {
      return null;
    }
    return value.replace("\r", "").replace("\n", "");
  }
}
