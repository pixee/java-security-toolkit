package io.openpixee.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Does a simple test to confirm that the escaping mechanism we use is working. Not meant to be an
 * exhaustive test of their security coverage.
 */
final class HtmlEncoderTest {

  @ParameterizedTest
  @CsvSource({"test_value,test_value", "<script>,&lt;script&gt;"})
  void it_escapes_correctly(final String before, final String after) {
    assertThat(HtmlEncoder.encode(before), equalTo(after));
  }
}
