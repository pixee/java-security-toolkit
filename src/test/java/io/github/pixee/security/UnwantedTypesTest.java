package io.github.pixee.security;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

final class UnwantedTypesTest {

  @Test
  void it_distinguishes_bad_types() {
    List<String> dangerousClassNameTokens = UnwantedTypes.dangerousClassNameTokens();
    assertThat(dangerousClassNameTokens, hasItem("com.sun.jna.Memory"));
    assertThat(dangerousClassNameTokens, not(hasItem("java.lang.String")));

    assertThat(UnwantedTypes.isUnwanted("com.sun.jna.Memory"), is(true));
    assertThat(UnwantedTypes.isUnwanted("my.acme.shaded.com.sun.jna.Memory"), is(true));
    assertThat(UnwantedTypes.isUnwanted("com.sun.jna.Memory$InnerType"), is(true));
    assertThat(UnwantedTypes.isUnwanted("java.lang.String"), is(false));
    assertThat(UnwantedTypes.isUnwanted("com.acme.FooBar"), is(false));
  }
}
