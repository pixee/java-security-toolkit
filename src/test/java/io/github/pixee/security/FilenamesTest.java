package io.github.pixee.security;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class FilenamesTest {

  @ParameterizedTest
  @ValueSource(strings = {"../foo.txt", "foo.txt", "/whatever/foo.txt", (char) 0x0 + "foo.txt"})
  void it_normalizes_paths(final String path) {
    assertThat(Filenames.toSimpleFileName(path), equalTo("foo.txt"));
  }

  @Test
  void it_normalizes_windows_path_safely() {
    assertThat(Filenames.toSimpleFileName("C:\\windows\\foo.txt"), equalTo("Cwindowsfoo.txt"));
  }

  @Test
  void it_returns_null_when_null_passed() {
    assertThat(Filenames.toSimpleFileName(null), is(nullValue()));
  }

  @Test
  void it_returns_empty_when_empty_passed() {
    assertThat(Filenames.toSimpleFileName(""), equalTo(""));
  }
}
