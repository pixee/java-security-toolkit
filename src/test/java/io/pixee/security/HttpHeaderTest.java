package io.pixee.security;

import static io.pixee.security.HttpHeader.stripNewlines;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.Test;

final class HttpHeaderTest {

  @Test
  void it_strips_newlines() {
    assertThat(stripNewlines(null), equalTo(null));
    assertThat(stripNewlines("foo bar"), equalTo("foo bar"));
    assertThat(stripNewlines("\nfoo bar\r"), equalTo("foo bar"));
  }
}
