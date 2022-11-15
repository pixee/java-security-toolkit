package io.openpixee.security;

import java.util.Objects;

/**
 * The set of protocols that we can allow (notice "ANY") is an option in {@link Urls} methods.
 *
 * @see Urls
 */
public enum UrlProtocol {
  /** A protocol indicating that _any_ protocol is allowed. */
  ANY("any"),

  /** HTTPS */
  HTTPS("https"),

  /** HTTP */
  HTTP("http"),

  /** FTP */
  FTP("ftp"),

  /** SMB */
  SMB("smb"),

  /** File */
  FILE("file"),

  /** Resource */
  RESOURCE("resource"),

  /** Gopher */
  GOPHER("gopher"),

  /**
   * News
   *
   * <p>https://www.ietf.org/archive/id/draft-ellermann-news-nntp-uri-11.html
   */
  NEWS("news"),

  /** JAR */
  JAR("jar"),

  /** mailto */
  MAILTO("mailto"),

  /** telnet */
  TELNET("telnet"),

  /** Classpath */
  CLASSPATH("classpath");

  private final String key;

  /**
   * @param key the protocol for the URL
   */
  UrlProtocol(final String key) {
    this.key = Objects.requireNonNull(key);
  }

  /** Return the given URL protocol */
  String getKey() {
    return key;
  }
}
