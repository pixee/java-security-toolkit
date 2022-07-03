package io.pixee.security;

import java.util.Objects;

/**
 * The set of protocols that we can allow (notice "ANY") is an option in {@link Urls} methods.
 *
 * @see Urls
 */
public enum UrlProtocol {
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

  UrlProtocol(final String key) {
    this.key = Objects.requireNonNull(key);
  }

  String getKey() {
    return key;
  }
}
