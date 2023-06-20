package io.github.pixee.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class ZipSecurityTest {

  @Test
  void it_doesnt_prevent_normal_zip_file_reads() throws IOException {
    ZipEntry entry = new ZipEntry("normal.txt");
    InputStream is = createZipFrom(entry);

    ZipInputStream hardenedStream =
        ZipSecurity.createHardenedInputStream(is, StandardCharsets.UTF_8);
    ZipEntry retrievedEntry = hardenedStream.getNextEntry();
    assertThat(retrievedEntry.getName(), equalTo("normal.txt"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"dir1/dir2/../normal.txt", "dir1/../normal.txt"})
  void it_doesnt_prevent_normal_zip_files_with_safe_escapes(String path) throws IOException {
    ZipEntry entry = new ZipEntry(path);
    InputStream is = createZipFrom(entry);

    ZipInputStream hardenedStream = ZipSecurity.createHardenedInputStream(is);
    ZipEntry retrievedEntry = hardenedStream.getNextEntry();
    assertThat(retrievedEntry.getName(), equalTo(path));
  }

  @ParameterizedTest
  @ValueSource(strings = {"../etc/whatever", "/foo/bar/../../../proc/whatever"})
  void it_prevents_escapes(String path) throws IOException {
    ZipEntry entry = new ZipEntry(path);
    InputStream is = createZipFrom(entry);

    ZipInputStream hardenedStream = ZipSecurity.createHardenedInputStream(is);
    assertThrows(SecurityException.class, hardenedStream::getNextEntry);
  }

  @Test
  void it_prevents_absolute_paths_in_zip_entries() throws IOException {
    ZipEntry entry = new ZipEntry("/foo.txt");
    InputStream is = createZipFrom(entry);

    ZipInputStream hardenedStream = ZipSecurity.createHardenedInputStream(is);
    assertThrows(SecurityException.class, hardenedStream::getNextEntry);
  }

  private InputStream createZipFrom(final ZipEntry entry) throws IOException {
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    ZipOutputStream zos = new ZipOutputStream(os);
    zos.putNextEntry(entry);
    zos.closeEntry();
    zos.close();

    return new ByteArrayInputStream(os.toByteArray());
  }
}
