package io.openpixee.security;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.Test;

final class UnwantedTypesTest {

  @Test
  void it_has_same_non_empty_set() {
    String[] unwantedTypes = UnwantedTypes.allArray();
    assertThat(unwantedTypes.length > 0, is(true));
    assertThat(UnwantedTypes.all(), hasItems(unwantedTypes));
  }
}
