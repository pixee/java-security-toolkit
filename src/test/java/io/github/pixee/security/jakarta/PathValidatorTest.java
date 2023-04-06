package io.github.pixee.security.jakarta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class PathValidatorTest {

  /**
   * Makes sure that {@link PathValidator#validateDispatcherPath(String)} protects against common
   * attack targets.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "/basic/absolute/WEB-INF/web.xml",
        "/null/bytes/WEB-INF/web.xml%00",
        "/double-slashes/bytes//WEB-INF//web.xml",
        "../relative/WEB-INF/web.xml",
        "../relative/..\\WEB-INF\\web.xml",
        "WEB-INF/classes/whatever.xml",
        "WEB-INF/lib/whatever.xml",
        "WEB-INF/./web.xml",
        "WEB-INF/test" + (char) 0x00
      })
  void it_protects_against_attacks(String safePath) {
    assertThrows(SecurityException.class, () -> PathValidator.validateDispatcherPath(safePath));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "test",
        "fine/WEB-INF/foo.jsp",
        "fine/WEB-INF\\jsps\\foo.jsp",
        "/WEB-INF/good.xsd",
        "/relative/../file.html"
      })
  void it_allows_normal_paths(String normalPath) {
    assertThat(PathValidator.validateDispatcherPath(normalPath), is(normalPath));
  }

  @Test
  void it_passes_null() {
    assertThat(PathValidator.validateDispatcherPath(null), is(nullValue()));
  }
}
