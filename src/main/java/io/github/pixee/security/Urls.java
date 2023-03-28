package io.github.pixee.security;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLStreamHandler;
import java.util.Set;

/**
 * This type exposes utilities to help developers protect against server-side request forgery (SSRF)
 * and any other possible attacks based on creating unvalidated URLs.
 *
 * <p>https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
 */
public final class Urls {

  /**
   * This is a convenience {@link Set} provided for most people who probably only want to allow
   * HTTP-based protocols.
   */
  public static Set<UrlProtocol> HTTP_PROTOCOLS = Set.of(UrlProtocol.HTTPS, UrlProtocol.HTTP);

  public static URL create(
      final String url, final Set<UrlProtocol> allowedProtocols, final HostValidator validator)
      throws MalformedURLException {
    final URL u = new URL(url);
    return create(u, allowedProtocols, validator);
  }

  /** Convenience method which delegates to {@link Urls#create(URL, Set, HostValidator)}. */
  public static URL create(
      final String protocol,
      final String host,
      final int port,
      final String file,
      final Set<UrlProtocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(protocol, host, port, file);
    return create(u, allowedProtocols, hostValidator);
  }

  /** Convenience method which delegates to {@link Urls#create(URL, Set, HostValidator)}. */
  public static URL create(
      final String protocol,
      final String host,
      final int port,
      final String file,
      final URLStreamHandler handler,
      final Set<UrlProtocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(protocol, host, port, file, handler);
    return create(u, allowedProtocols, hostValidator);
  }

  /** Convenience method which delegates to {@link Urls#create(URL, Set, HostValidator)}. */
  public static URL create(
      final URL context,
      final String spec,
      final Set<UrlProtocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(context, spec);
    return create(u, allowedProtocols, hostValidator);
  }

  /** Convenience method which delegates to {@link Urls#create(URL, Set, HostValidator)}. */
  public static URL create(
      final URL context,
      final String spec,
      final URLStreamHandler handler,
      final Set<UrlProtocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(context, spec, handler);
    return create(u, allowedProtocols, hostValidator);
  }

  /** Convenience method which delegates to {@link Urls#create(URL, Set, HostValidator)}. */
  public static URL create(
      final String protocol,
      final String host,
      final String file,
      final Set<UrlProtocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(protocol, host, file);
    return create(u, allowedProtocols, hostValidator);
  }

  /**
   * Open a connection with some common-sense security checks in mind that will massively reduce the
   * likelihood of meaningful exploitation. Users can specify a set of allowed protocols or host
   * patterns.
   *
   * @param u the URL to create
   * @param hostValidator a {@link HostValidator} which confirms the intended host is allowed to be
   *     visited
   * @param allowedProtocols a {@link Set} of {@link UrlProtocol}, of which one must be the protocol
   *     of the created URL -- empty or null mean any protocol is allowed
   */
  private static URL create(
      final URL u, final Set<UrlProtocol> allowedProtocols, final HostValidator hostValidator) {
    checkProtocolAllowed(u.getProtocol(), allowedProtocols);
    checkHostsAllowed(u.getHost(), hostValidator);
    return u;
  }

  private static void checkHostsAllowed(final String host, final HostValidator hostValidator) {
    if (!hostValidator.isAllowed(host)) {
      throw new SecurityException("disallowed host: " + host);
    }
  }

  private static void checkProtocolAllowed(
      final String parsedProtocol, final Set<UrlProtocol> protocols) {
    if ((protocols != null && !protocols.isEmpty()) && (!protocols.contains(UrlProtocol.ANY))) {
      for (UrlProtocol allowedProtocol : protocols) {
        final String key = allowedProtocol.getKey();
        if (parsedProtocol.equalsIgnoreCase(key)) {
          return;
        }
      }
      throw new SecurityException("disallowed protocol: " + parsedProtocol);
    }
  }
}
