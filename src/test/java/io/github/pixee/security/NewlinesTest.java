package io.github.pixee.security;

import static io.github.pixee.security.Newlines.stripAll;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.Test;

final class NewlinesTest {

  @Test
  void it_strips_newlines() {
    assertThat(stripAll(null), equalTo(null));
    assertThat(stripAll("foo bar"), equalTo("foo bar"));
    assertThat(stripAll("\nfoo bar\r"), equalTo("foo bar"));
  }
}
