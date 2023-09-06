package io.github.pixee.security;

import static io.github.pixee.security.J8ApiBridge.setOf;

import java.lang.reflect.Modifier;
import java.util.Set;

/**
 * This type exposes helper methods that will help defend against attacks involving reflection and
 * classloading.
 */
public final class Reflection {

  private Reflection() {}

  private static final Set<ReflectionRestrictions> defaultRestrictions =
      setOf(ReflectionRestrictions.MUST_NOT_INVOLVE_CODE_EXECUTION);

  /**
   * Provide the default restrictions for loading a type that will work for the vast majority of
   * applications.
   *
   * @return a set of restrictions that are suitable for broad use in protecting reflection
   *     operations
   */
  public static Set<ReflectionRestrictions> defaultRestrictions() {
    return defaultRestrictions;
  }

  /**
   * This method sandboxes the classloading to prevent possibly types outside the expected package
   * from being loaded, with no other restrictions enforced.
   *
   * @param name the name of the type to load
   * @param expectedPackage the package name we expect the loaded type to be in
   * @return the result of {@link Class#forName(String)}, if the type is
   * @throws ClassNotFoundException if the class is not found
   * @throws SecurityException if the {@link Class} isn't in the expected package
   */
  public static Class<?> loadAndVerifyPackage(final String name, final String expectedPackage)
      throws ClassNotFoundException {
    if (expectedPackage == null) {
      throw new IllegalArgumentException("expectedPackage");
    }
    Class<?> type = loadAndVerify(name, defaultRestrictions());
    String loadedTypeName = type.getName();
    if (!loadedTypeName.startsWith(expectedPackage)) {
      throw new SecurityException("unexpected package on type: " + loadedTypeName);
    }
    return type;
  }

  /**
   * Helper method that delegates {@link Reflection#loadAndVerify(String, Set)}
   *
   * @param name the name of the type to load
   * @throws ClassNotFoundException if the class is not found
   * @return the result of {@link Class#forName(String)}, if it passes the default restrictions
   */
  public static Class<?> loadAndVerify(final String name) throws ClassNotFoundException {
    return loadAndVerify(name, defaultRestrictions());
  }

  /**
   * This method sandboxes the classloading to prevent possibly dangerous types from being loaded,
   * using the default restrictions.
   *
   * @param name the name of the type to load
   * @param initialize whether to initialize the class, passed to {@link Class#forName(String,
   *     boolean, ClassLoader)}
   * @param loader the ClassLoader to use, passed to {@link Class#forName(String, boolean,
   *     ClassLoader)}
   * @throws ClassNotFoundException if the class is not found
   * @return the result of {@link Class#forName(String)}, if it passes the default restrictions
   */
  public static Class<?> loadAndVerify(
      final String name, final boolean initialize, final ClassLoader loader)
      throws ClassNotFoundException {
    return loadAndVerify(
        name, defaultRestrictions(), () -> Class.forName(name, initialize, loader));
  }

  /**
   * This method sandboxes the classloading to prevent possibly dangerous types from being loaded.
   *
   * @param name the name of the type to load
   * @param restrictions the set of {@link ReflectionRestrictions} to apply
   * @return the result of {@link Class#forName(String)}, if it passes the restrictions
   * @throws ClassNotFoundException if the class is not found
   */
  public static Class<?> loadAndVerify(
      final String name, final Set<ReflectionRestrictions> restrictions)
      throws ClassNotFoundException {
    return loadAndVerify(name, restrictions, () -> Class.forName(name));
  }

  private static Class<?> loadAndVerify(
      final String name,
      final Set<ReflectionRestrictions> restrictions,
      final ClassSupplier classSupplier)
      throws ClassNotFoundException {

    // we can do this check up front before we even load the type
    if (restrictions.contains(ReflectionRestrictions.MUST_NOT_INVOLVE_CODE_EXECUTION)) {
      for (String codeLoadingPackage : codeLoadingPackages) {
        if (name.startsWith(codeLoadingPackage)) {
          throw new SecurityException(typeNotAllowedMessage);
        }
      }
    }

    // load the type so we can do the other checks
    final Class<?> type = classSupplier.get();

    if (restrictions.contains(ReflectionRestrictions.MUST_BE_PUBLIC)) {
      final int modifiers = type.getModifiers();
      if (!Modifier.isPublic(modifiers)) {
        throw new SecurityException("type must be public");
      }
    }

    if (restrictions.contains(ReflectionRestrictions.MUST_NOT_INVOLVE_CODE_EXECUTION)) {
      if (codeLoadingTypes.contains(type)) {
        throw new SecurityException(typeNotAllowedMessage);
      }
    }
    return type;
  }

  private static final Set<Class<?>> codeLoadingTypes =
      setOf(
          java.lang.Runtime.class,
          java.lang.ProcessBuilder.class,
          java.lang.Class.class,
          java.lang.ClassLoader.class);

  private static final Set<String> codeLoadingPackages =
      setOf(
          "java.lang.invoke.",
          "org.apache.commons.collections.functors.",
          "bsh.",
          "mozilla.javascript.",
          "groovy.",
          "org.python.");

  private interface ClassSupplier {
    Class<?> get() throws ClassNotFoundException;
  }

  private static final String typeNotAllowedMessage = "type not allowed";
}
