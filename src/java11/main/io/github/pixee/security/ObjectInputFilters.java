package io.github.pixee.security;

import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Objects;

/**
 * This type exposes helper methods that will help defend against Java deserialization attacks
 * leveraging the Java 9+ API {@link ObjectInputFilter}.
 *
 * <p>For more information on deserialization checkout the <a
 * href="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html">OWASP
 * Cheat Sheet</a>.
 */
public final class ObjectInputFilters {

  private ObjectInputFilters() {}

  /**
   * This method returns an {@link ObjectInputFilter} for use in {@link
   * java.io.ObjectInputStream#setObjectInputFilter(ObjectInputFilter)} to protect against
   * deserialization code execution attacks. This method is meant for Java 9+ apps since it relies
   * on methods introduced in that version.
   *
   * @return an {@link ObjectInputFilter} to be used in {@link
   *     ObjectInputStream#setObjectInputFilter(ObjectInputFilter)}
   */
  public static ObjectInputFilter getHardenedObjectFilter() {
    return basicGadgetDenylistFilter;
  }

  /**
   * This method attempts to install an {@link ObjectInputFilter} if one doesn't exist in order to
   * protect against deserialization code execution attacks. This is meant for Java 9+ apps since it
   * relies on methods introduced in that version.
   *
   * <p>Note: code weavers can't weave this code directly into arbitrary code because it forces you
   * to choose what to do in the try-catch block. An empty catch block may cause checkstyle
   * violations, and will look more disruptive.
   *
   * @param ois the reader to secure
   */
  public static void enableObjectFilterIfUnprotected(final ObjectInputStream ois) {
    ObjectInputFilter objectInputFilter = ois.getObjectInputFilter();
    if (objectInputFilter == null) {
      try {
        ois.setObjectInputFilter(basicGadgetDenylistFilter);
      } catch (Exception e) {
        /*
         * This is expected when the SecurityManager has an opinion about this, or maybe another thread has installed an
         * ObjectInputFilter, or something else unexpected.
         */
      }
    }
  }

  /**
   * This method returns an {@link ObjectInputFilter} for use in {@link
   * java.io.ObjectInputStream#setObjectInputFilter(ObjectInputFilter)} to protect against
   * deserialization code execution attacks. This method is meant for Java 9+ apps since it relies
   * on methods introduced in that version.
   *
   * <p>This method attempts to combine the default protections of this utility with an existing
   * filter in the app code.
   *
   * @param existingFilter the existing filter for the call about to take place, so we can work in
   *     tandem with it
   * @return an {@link ObjectInputFilter} to be used in {@link
   *     ObjectInputStream#setObjectInputFilter(ObjectInputFilter)}
   */
  public static ObjectInputFilter createCombinedHardenedObjectFilter(
      final ObjectInputFilter existingFilter) {
    if (existingFilter == null) {
      return basicGadgetDenylistFilter;
    }
    return new CombinedObjectInputFilter(existingFilter);
  }

  private static class CombinedObjectInputFilter implements ObjectInputFilter {
    private final ObjectInputFilter originalFilter;

    private CombinedObjectInputFilter(final ObjectInputFilter originalFilter) {
      this.originalFilter = Objects.requireNonNull(originalFilter);
    }

    @Override
    public Status checkInput(final FilterInfo filterInfo) {
      if (Status.REJECTED.equals(basicGadgetDenylistFilter.checkInput(filterInfo))) {
        return Status.REJECTED;
      }
      return originalFilter.checkInput(filterInfo);
    }
  }

  private static final ObjectInputFilter basicGadgetDenylistFilter =
      ObjectInputFilter.Config.createFilter(
          "!" + String.join("*;!", UnwantedTypes.dangerousClassNameTokens()));
}
