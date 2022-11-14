package io.openpixee.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import org.junit.jupiter.api.Test;

final class BoundedLineReaderTest {

  @Test
  void doesnt_read_more_than_specified() {
    Reader br = new BufferedReader(new StringReader("123\n456"));
    assertThrows(SecurityException.class, () -> BoundedLineReader.readLine(br, 2));
  }

  @Test
  void two_readlines_work() throws IOException {
    BufferedReader br = new BufferedReader(new StringReader("123\n456"));
    assertThat(BoundedLineReader.readLine(br, 3), equalTo("123"));
    assertThat(BoundedLineReader.readLine(br, 3), equalTo("456"));

    br = new BufferedReader(new StringReader("12"));
    assertThat(BoundedLineReader.readLine(br, 2), equalTo("12"));
  }
}
