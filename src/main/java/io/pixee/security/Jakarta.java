package io.pixee.security;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import org.apache.commons.io.FilenameUtils;

/** This type exposes helper methods that will help defend against Jakarta EE-specific attacks. */
public final class Jakarta {

  private interface PathNormalizer {
    String normalizeOrNull(String path);
  }

  private static class ApacheFilenameUtilsPathNormalizer implements PathNormalizer {
    @Override
    public String normalizeOrNull(final String path) {
      return FilenameUtils.normalize(path, true);
    }
  }

  private static class UriPathNormalizer implements PathNormalizer {
    @Override
    public String normalizeOrNull(String path) {
      try {
        URI uri = new URI(path);
        uri = uri.normalize();
        return uri.getPath();
      } catch (URISyntaxException e) {
        // this is strange for sure, but do we have enough confidence to block?
      }
      return null;
    }
  }

  private static final List<PathNormalizer> pathValidators =
      List.of(new ApacheFilenameUtilsPathNormalizer(), new UriPathNormalizer());

  /**
   * Validates the path argument to {@link javax.servlet.http.HttpServletRequest#getRequestDispatcher()}, which could be used
   * to gain access to sensitive assets like configuration files, code files, etc. This method only
   * protects against assets that are common amongst all apps, and thus represent easier targets for
   * attackers. If the attacker is using brute force or has insider knowledge, they could still
   * possibly find their way into other sensitive assets.
   *
   * @param path an argument to HttpServletRequest#getRequestDispatcher() to validate
   * @return the same String as was passed in
   * @throws SecurityException if the path seems to be targeting sensitive Jakarta web application
   *     assets
   */
  public static String validateForwardPath(final String path) {
    if (path == null) {
      return null;
    }
    String unixPath = path.replace('\\', '/');
    if (unixPath.indexOf(0x00) != -1) {
      throw new SecurityException(unsafePathMessage);
    }
    for (PathNormalizer pathValidator : pathValidators) {
      final String normalizedPath = pathValidator.normalizeOrNull(unixPath);
      if (normalizedPath != null) {
        runCheckOn(normalizedPath);
        return path;
      }
    }
    return path;
  }

  private static void runCheckOn(final String normalizedPath) {
    for (String unsafeDestination : unsafeDestinations) {
      if (normalizedPath.contains(unsafeDestination)) {
        throw new SecurityException(unsafePathMessage);
      }
    }
  }

  private static final String unsafePathMessage = "unsafe forward destination specified";
  private static final List<String> unsafeDestinations =
      List.of("WEB-INF/web.xml", "WEB-INF/classes/", "WEB-INF/lib/");
}
