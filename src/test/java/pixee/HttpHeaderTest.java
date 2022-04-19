package pixee;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static pixee.HttpHeader.stripNewlines;

import org.junit.jupiter.api.Test;

final class HttpHeaderTest {

  @Test
  void it_strips_newlines() {
    assertThat(stripNewlines("foo bar"), equalTo("foo bar"));
    assertThat(stripNewlines("\nfoo bar\r"), equalTo("foo bar"));
  }
}
