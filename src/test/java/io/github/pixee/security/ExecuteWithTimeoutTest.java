package io.github.pixee.security;

import org.junit.jupiter.api.Test;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class ExecuteWithTimeoutTest {

  @Test
  void it_executes_within_timeout_and_returns(){
    Pattern pat = Pattern.compile("string");
    String input = "some very long string";
    Matcher matcher = pat.matcher(input);
    boolean result = ExecuteWithTimeout.executeWithTimeout(() -> matcher.find(), 5000);
    assertThat(result, is(equalTo(true)));
  }

  @Test
  void it_throws_exception_due_to_timeout(){
    Pattern pat = Pattern.compile("string");
    String input = "some very long string";
    Matcher matcher = pat.matcher(input);
    RuntimeException exception = assertThrows(
        RuntimeException.class,
        () -> ExecuteWithTimeout.executeWithTimeout(() -> matcher.find(), 0)
        );
    assertThat(exception.getMessage(), is(equalTo("Failed to execute within time limit.")));
  }

}
