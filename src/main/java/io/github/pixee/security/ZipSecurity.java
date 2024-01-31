package io.github.pixee.security;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * This type exposes helper methods to deal with attacks related to Zipping operations, most notably
 * the "zip slip" attack.
 */
public final class ZipSecurity {

  private ZipSecurity() {}

  /**
   * Returns a {@link ZipInputStream} that will check to make sure that paths encountered in the zip
   * aren't absolute and don't contain escapes ("..") towards directories outside the zip's root.
   */
  public static ZipInputStream createHardenedInputStream(
      final InputStream stream, final Charset charset) {
    return new HardenedZipInputStream(stream, charset);
  }

  /**
   * Returns a {@link ZipInputStream} that will check to make sure that paths encountered in the zip
   * aren't absolute and don't contain escapes ("..") towards directories beyond the root of the
   * zip.
   */
  public static ZipInputStream createHardenedInputStream(final InputStream stream) {
    return new HardenedZipInputStream(stream);
  }

  private static class HardenedZipInputStream extends ZipInputStream {

    private HardenedZipInputStream(final InputStream in) {
      super(in);
    }

    private HardenedZipInputStream(final InputStream in, final Charset charset) {
      super(in, charset);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Also checks to see that the path isn't absolute (starts with a root path), doesn't contain
     * escapes that lead above the root of the zip.
     */
    @Override
    public ZipEntry getNextEntry() throws IOException {
      final ZipEntry entry = super.getNextEntry();
      final String name = entry.getName();

      if (!"".equals(name.trim())) {
        if (isRootFileEntry(name)) {
          throw new SecurityException("encountered zip file path that is absolute: " + name);
        }
        if (containsEscapesAndTargetsBelowRoot(name)) {
          throw new SecurityException("path to sensitive locations contained escapes: " + name);
        }
      }
      return entry;
    }

    private boolean containsEscapesAndTargetsBelowRoot(final String name) {
      if (name.contains("../") || name.contains("..\\")) {
        try {
          if (isBelowOrSisterToCurrentDirectory(name)) {
            return true;
          }
        } catch (IOException e) {
          // we suppose this may happen in normal operation so best not to do anything
        }
      }
      return false;
    }

    private boolean isBelowOrSisterToCurrentDirectory(final String untrustedFileWithEscapes) throws IOException {
      // Get the absolute path of the current directory
      final File currentDirectory = new File("").getCanonicalFile();
      final Path currentPathRoot = currentDirectory.toPath();
      // Get the absolute path of the untrusted file
      final File untrustedFile = new File(currentDirectory, untrustedFileWithEscapes);
      final Path pathWithEscapes = untrustedFile.getCanonicalFile().toPath();
      return !pathWithEscapes.startsWith(currentPathRoot);
    }

    private boolean isRootFileEntry(final String name) {
      return name.startsWith("/");
    }
  }
}
