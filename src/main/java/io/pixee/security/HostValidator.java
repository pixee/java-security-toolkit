package io.pixee.security;

import java.net.URL;
import java.util.Set;
import java.util.regex.Pattern;

/** A type that validates hosts to be connected. */
public interface HostValidator {

  /**
   * Decide whether a host is allowed to be reached
   *
   * @param host the host of a {@link URL}
   * @return true, if the application can connect to the host, false otherwise
   */
  boolean isAllowed(String host);

  /** A {@link HostValidator} that allows all hosts. */
  HostValidator ALLOW_ALL = host -> true;

  /**
   * A {@link HostValidator} that prevents access to common infrastructure targets. Right now this
   * only includes likely gateway IP address and AWS Metadata services host, but hopefully over time
   * we can identify more. Note that changes to this set should also include the "integer" version
   * of the IP address, which can be generated with utilities on the web.
   */
  HostValidator DENY_COMMON_INFRASTRUCTURE_TARGETS =
      new HostValidator() {
        @Override
        public boolean isAllowed(final String host) {
          final String cleanedHost = host.trim();
          return !knownInfrastructureTargets.contains(cleanedHost);
        }

        private final Set<String> knownInfrastructureTargets =
            Set.of("192.168.1.1", "3232235777", "169.254.169.254", "2852039166");
      };

  /** Return a {@link HostValidator} that will validate the host name against the "allowPattern". */
  static HostValidator fromAllowedHostPattern(final Pattern allowPattern) {
    return new PatternBasedHostValidator(allowPattern);
  }
}
