package pixee;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLStreamHandler;
import java.util.Objects;
import java.util.Set;

/**
 * This type exposes utilities to help developers protect against server-side request forgery
 * (SSRF).
 *
 * <p>https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
 */
public final class SSRF {

  /** The set of protocols that we can allow (notice "ANY") is an option. */
  public enum Protocol {
    ANY("any"),
    HTTPS("https"),
    HTTP("http"),
    FTP("ftp"),
    SMB("smb"),
    FILE("file"),
    RESOURCE("resource"),
    GOPHER("gopher"),
    NEWS("new"),
    JAR("jar"),
    MAILTO("mailto"),
    TELNET("telnet"),
    CLASSPATH("classpath");

    private final String key;

    Protocol(final String key) {
      this.key = Objects.requireNonNull(key);
    }

    private String getKey() {
      return key;
    }
  }

  /**
   * This is a convenience {@link Set} provided for most people who probably only want to allow
   * HTTP-based protocols.
   */
  public static Set<Protocol> HTTP_PROTOCOLS = Set.of(Protocol.HTTPS, Protocol.HTTP);

  public static URL createSafeURL(
      final String url, final Set<Protocol> allowedProtocols, final HostValidator validator)
      throws MalformedURLException {
    final URL u = new URL(url);
    return createSafeURL(u, allowedProtocols, validator);
  }

  /** Convenience method which delegates to {@link SSRF#createSafeURL(URL, Set, HostValidator)}. */
  public static URL createSafeURL(
      final String url,
      final String host,
      final int port,
      final String file,
      final Set<Protocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(url, host, port, file);
    return createSafeURL(u, allowedProtocols, hostValidator);
  }

  /** Convenience method which delegates to {@link SSRF#createSafeURL(URL, Set, HostValidator)}. */
  public static URL createSafeURL(
      final String url,
      final String host,
      final int port,
      final String file,
      final URLStreamHandler handler,
      final Set<Protocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(url, host, port, file, handler);
    return createSafeURL(u, allowedProtocols, hostValidator);
  }

  /** Convenience method which delegates to {@link SSRF#createSafeURL(URL, Set, HostValidator)}. */
  public static URL createSafeURL(
      final URL url,
      final String spec,
      final Set<Protocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(url, spec);
    return createSafeURL(u, allowedProtocols, hostValidator);
  }

  /** Convenience method which delegates to {@link SSRF#createSafeURL(URL, Set, HostValidator)}. */
  public static URL createSafeURL(
      final URL url,
      final String spec,
      final URLStreamHandler handler,
      final Set<Protocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(url, spec, handler);
    return createSafeURL(u, allowedProtocols, hostValidator);
  }

  /** Convenience method which delegates to {@link SSRF#createSafeURL(URL, Set, HostValidator)}. */
  public static URL createSafeURL(
      final String protocol,
      final String host,
      final String file,
      final Set<Protocol> allowedProtocols,
      final HostValidator hostValidator)
      throws MalformedURLException {
    final URL u = new URL(protocol, host, file);
    return createSafeURL(u, allowedProtocols, hostValidator);
  }

  /**
   * Open a connection with some common-sense security checks in mind that will massively reduce the
   * likelihood of meaningful exploitation. Users can specify a set of allowed protocols or host
   * patterns.
   *
   * @param u the URL to create
   * @param hostValidator a {@link HostValidator} which confirms the intended host is allowed to be
   *     visited
   * @param allowedProtocols a {@link Set} of {@link Protocol}, of which one must be the protocol of
   *     the created URL -- empty or null mean any protocol is allowed
   */
  private static URL createSafeURL(
      final URL u, final Set<Protocol> allowedProtocols, final HostValidator hostValidator) {
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
      final String parsedProtocol, final Set<Protocol> protocols) {
    if ((protocols != null && !protocols.isEmpty()) && (!protocols.contains(Protocol.ANY))) {
      for (Protocol allowedProtocol : protocols) {
        final String key = allowedProtocol.getKey();
        if (parsedProtocol.equalsIgnoreCase(key)) {
          return;
        }
      }
      throw new SecurityException("disallowed protocol: " + parsedProtocol);
    }
  }
}
