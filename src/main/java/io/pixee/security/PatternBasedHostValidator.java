package io.pixee.security;

import java.util.Objects;
import java.util.regex.Pattern;

/** A {@link HostValidator} that allows only hosts that match a certain pattern. */
final class PatternBasedHostValidator implements HostValidator {

  private final Pattern allowPattern;

  PatternBasedHostValidator(final Pattern allowPattern) {
    this.allowPattern = Objects.requireNonNull(allowPattern);
  }

  @Override
  public boolean isAllowed(final String host) {
    return allowPattern.matcher(host).matches();
  }
}
