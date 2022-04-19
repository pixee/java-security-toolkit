package io.pixee.security;

import java.lang.reflect.Modifier;
import java.util.Set;

/**
 * This type exposes helper methods that will help defend against attacks involving reflection and
 * classloading.
 */
public final class Reflection {

  private Reflection() {}

  public enum Restrictions {
    MUST_BE_PUBLIC,
    MUST_NOT_INVOLVE_CODE_EXECUTION
  }

  private static final Set<Restrictions> defaultRestrictions =
      Set.of(Restrictions.MUST_NOT_INVOLVE_CODE_EXECUTION);

  /**
   * Provide the default restrictions for loading a type that will work for the vast, vast majority
   * of applications.
   */
  public static Set<Restrictions> defaultRestrictions() {
    return defaultRestrictions;
  }

  /** Helper method that delegates {@link Reflection#loadAndVerify(String, Set)} */
  public static Class<?> loadAndVerify(final String name) throws ClassNotFoundException {
    return loadAndVerify(name, defaultRestrictions());
  }

  /**
   * This method sandboxes the classloading to prevent possibly dangerous types from being loaded.
   *
   * @param name the name of the type to load
   * @param restrictions the set of {@link Restrictions} to apply
   * @return the result of {@link Class#forName(String)}, if it passes the restrictions
   */
  public static Class<?> loadAndVerify(final String name, final Set<Restrictions> restrictions)
      throws ClassNotFoundException {

    // we can do this check up front before we even load the type
    if (restrictions.contains(Restrictions.MUST_NOT_INVOLVE_CODE_EXECUTION)) {
      for (String codeLoadingPackage : codeLoadingPackages) {
        if (name.startsWith(codeLoadingPackage)) {
          throw new SecurityException(typeNotAllowedMessage);
        }
      }
    }

    // load the type so we can do the other checks
    final Class<?> type = Class.forName(name);

    if (restrictions.contains(Restrictions.MUST_BE_PUBLIC)) {
      final int modifiers = type.getModifiers();
      if (!Modifier.isPublic(modifiers)) {
        throw new SecurityException("type must be public");
      }
    }

    if (restrictions.contains(Restrictions.MUST_NOT_INVOLVE_CODE_EXECUTION)) {
      if (codeLoadingTypes.contains(type)) {
        throw new SecurityException(typeNotAllowedMessage);
      }
    }
    return type;
  }

  private static final Set<Class<?>> codeLoadingTypes =
      Set.of(
          java.lang.Runtime.class,
          java.lang.ProcessBuilder.class,
          java.lang.Class.class,
          java.lang.ClassLoader.class);

  private static final Set<String> codeLoadingPackages =
      Set.of(
          "java.lang.invoke.",
          "org.apache.commons.collections.functors.",
          "bsh.",
          "mozilla.javascript.",
          "groovy.",
          "org.python.");

  private static final String typeNotAllowedMessage = "type not allowed";
}
