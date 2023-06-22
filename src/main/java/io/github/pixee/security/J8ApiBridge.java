package io.github.pixee.security;

import java.util.*;

final class J8ApiBridge {

  private J8ApiBridge() {}

  /** A replacement API for Set.of(), which doesn't exist in Java 8, which we target. */
  static <T> Set<T> setOf(final T... t) {
    return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(t)));
  }

  /** A replacement API for List.of(), which doesn't exist in Java 8, which we target. */
  static <T> List<T> listOf(final T... t) {
    return Collections.unmodifiableList(new ArrayList<>(Arrays.asList(t)));
  }
}
