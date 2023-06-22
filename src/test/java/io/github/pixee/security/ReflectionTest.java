package io.github.pixee.security;

import static io.github.pixee.security.J8ApiBridge.setOf;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class ReflectionTest {

  @ParameterizedTest
  @ValueSource(
      strings = {"java.lang.Runtime", "java.lang.ClassLoader", "java.lang.invoke.MethodHandle"})
  void it_protects_dangerous_reflection(final String type) {
    assertThrows(
        SecurityException.class,
        () ->
            Reflection.loadAndVerify(
                type, setOf(ReflectionRestrictions.MUST_NOT_INVOLVE_CODE_EXECUTION)));

    // run the same test and confirm that the defaultRestrictions() returns this
    assertThrows(SecurityException.class, () -> Reflection.loadAndVerify(type));
  }

  @Test
  void it_enforces_public_restriction() throws ClassNotFoundException {

    // this test class is not public so we shouldn't be able to load it without blowing up
    assertThrows(
        SecurityException.class,
        () ->
            Reflection.loadAndVerify(
                ReflectionTest.class.getName(), setOf(ReflectionRestrictions.MUST_BE_PUBLIC)));

    // the type we're testing is public and so we should be able to load it
    Reflection.loadAndVerify(
        Reflection.class.getName(), setOf(ReflectionRestrictions.MUST_BE_PUBLIC));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "java.lang.Integer",
        "io.github.pixee.security.CommandLine",
        "org.apache.commons.io.FileUtils"
      })
  void it_loads_normal_classes(final String typeName) throws ClassNotFoundException {
    Class<?> type = Reflection.loadAndVerify(typeName);
    assertThat(type, is(not(nullValue())));
  }

  @Test
  void it_loads_with_expected_package() throws ClassNotFoundException {
    assertThat(
        Reflection.loadAndVerifyPackage("java.lang.String", "java.lang"), equalTo(String.class));

    assertThrows(
        SecurityException.class,
        () -> Reflection.loadAndVerifyPackage("java.lang.String", "java.io"));

    assertThrows(
        IllegalArgumentException.class,
        () -> Reflection.loadAndVerifyPackage("java.lang.String", null));
  }
}
