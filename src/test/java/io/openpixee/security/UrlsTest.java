package io.openpixee.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

final class UrlsTest {

  @Test
  void it_allows_good_protocols() throws MalformedURLException {
    URL url =
        Urls.create(
            "https://foo:bar@zxc.com/endpt?foo",
            Set.of(UrlProtocol.HTTPS),
            HostValidator.ALLOW_ALL);
    assertThat(url, is(not(nullValue())));
    assertThat(url.getHost(), equalTo("zxc.com"));
    assertThat(url.getProtocol(), equalTo("https"));
    assertThat(url.getPath(), equalTo("/endpt"));
    assertThat(url.getQuery(), equalTo("foo"));
  }

  @Test
  void exposed_field_allows_http_protocols() throws MalformedURLException {
    URL url = Urls.create("https://zxc.com/", Urls.HTTP_PROTOCOLS, HostValidator.ALLOW_ALL);
    assertThat(url, is(not(nullValue())));
    assertThat(url.getProtocol(), equalTo("https"));

    url = Urls.create("http://zxc.com/", Urls.HTTP_PROTOCOLS, HostValidator.ALLOW_ALL);
    assertThat(url, is(not(nullValue())));
    assertThat(url.getProtocol(), equalTo("http"));
  }

  interface UrlFactory {
    URL createUrl() throws MalformedURLException;
  }

  public static Stream<Arguments> urlFactories() {
    return Stream.of(
        Arguments.of(
            (UrlFactory)
                () ->
                    Urls.create(
                        "ftp",
                        "example.org",
                        21,
                        "foo.zip",
                        Set.of(UrlProtocol.FTP),
                        HostValidator.ALLOW_ALL)),
        Arguments.of(
            (UrlFactory)
                () ->
                    Urls.create(
                        "ftp",
                        "example.org",
                        21,
                        "foo.zip",
                        null,
                        Set.of(UrlProtocol.FTP),
                        HostValidator.ALLOW_ALL)),
        Arguments.of(
            (UrlFactory)
                () ->
                    Urls.create(
                        new URL("ftp://example.org:21/"),
                        "foo.zip",
                        Set.of(UrlProtocol.FTP),
                        HostValidator.ALLOW_ALL)),
        Arguments.of(
            (UrlFactory)
                () ->
                    Urls.create(
                        new URL("ftp://example.org:21/"),
                        "foo.zip",
                        null,
                        Set.of(UrlProtocol.FTP),
                        HostValidator.ALLOW_ALL)));
  }

  @ParameterizedTest
  @MethodSource("urlFactories")
  void it_works_with_all_signatures(UrlFactory urlFactory) throws MalformedURLException {
    URL url = urlFactory.createUrl();
    assertThat(url.getProtocol(), equalTo("ftp"));
    assertThat(url.getHost(), equalTo("example.org"));
    assertThat(url.getPort(), equalTo(21));
    assertThat(url.getFile(), isOneOf("/foo.zip", "foo.zip"));
  }

  @Test
  void it_creates_without_port_specified() throws MalformedURLException {
    URL url =
        Urls.create(
            "ftp", "example.org", "foo.zip", Set.of(UrlProtocol.FTP), HostValidator.ALLOW_ALL);
    assertThat(url.getProtocol(), equalTo("ftp"));
    assertThat(url.getHost(), equalTo("example.org"));
    assertThat(url.getPort(), equalTo(-1));
    assertThat(url.getFile(), isOneOf("foo.zip"));
  }

  @Test
  void it_allows_any_host_when_none_specified() throws MalformedURLException {
    Urls.create("https://foo:bar@zxc.com/endpt?foo", Set.of(), HostValidator.ALLOW_ALL);
  }

  @Test
  void it_allows_any_protocol_when_none_specified() throws MalformedURLException {
    Urls.create("https://foo:bar@zxc.com/endpt?foo", Set.of(), HostValidator.ALLOW_ALL);
    Urls.create("https://foo:bar@zxc.com/endpt?foo", null, HostValidator.ALLOW_ALL);
    Urls.create(
        "https://foo:bar@zxc.com/endpt?foo", Set.of(UrlProtocol.ANY), HostValidator.ALLOW_ALL);
  }

  @Test
  void it_disallows_bad_protocols() {
    assertThrows(
        SecurityException.class,
        () -> {
          Urls.create("http://etc/passwd", Set.of(UrlProtocol.FTP), HostValidator.ALLOW_ALL);
        });
  }

  @Test
  void it_disallows_bad_domains() throws MalformedURLException {
    HostValidator allowsOnlyGoodDotCom =
        HostValidator.fromAllowedHostPattern(Pattern.compile("good\\.com"));
    Urls.create("https://good.com/", Set.of(UrlProtocol.HTTPS), allowsOnlyGoodDotCom);
    assertThrows(
        SecurityException.class,
        () -> {
          Urls.create("https://evil.com/", Set.of(UrlProtocol.HTTPS), allowsOnlyGoodDotCom);
        });
  }

  @Test
  void it_blocks_know_bad_hosts_when_asked() throws MalformedURLException {
    // all hosts are allowed so this should work
    String awsMetadataUrl = "http://169.254.169.254/latest/meta-data";
    Urls.create(awsMetadataUrl, Set.of(UrlProtocol.ANY), HostValidator.ALLOW_ALL);

    // now we try with the "block the few known bad places"
    assertThrows(
        SecurityException.class,
        () -> {
          Urls.create(
              awsMetadataUrl,
              Set.of(UrlProtocol.ANY),
              HostValidator.DENY_COMMON_INFRASTRUCTURE_TARGETS);
        });
  }
}
