package io.pixee.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class ZipTest {

  @Test
  void it_doesnt_prevent_normal_zip_file_reads() throws IOException {
    var entry = new ZipEntry("normal.txt");
    var is = createZipFrom(entry);

    var hardenedStream = Zip.createHardenedZipInputStream(is);
    var retrievedEntry = hardenedStream.getNextEntry();
    assertThat(retrievedEntry.getName(), equalTo("normal.txt"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"dir1/dir2/../normal.txt", "dir1/../normal.txt"})
  void it_doesnt_prevent_normal_zip_files_with_safe_escapes(String path) throws IOException {
    var entry = new ZipEntry(path);
    var is = createZipFrom(entry);

    var hardenedStream = Zip.createHardenedZipInputStream(is);
    var retrievedEntry = hardenedStream.getNextEntry();
    assertThat(retrievedEntry.getName(), equalTo(path));
  }

  @ParameterizedTest
  @ValueSource(strings = {"../etc/whatever", "/foo/bar/../../../proc/whatever"})
  void it_prevents_escapes(String path) throws IOException {
    var entry = new ZipEntry(path);
    var is = createZipFrom(entry);

    var hardenedStream = Zip.createHardenedZipInputStream(is);
    assertThrows(SecurityException.class, hardenedStream::getNextEntry);
  }

  @Test
  void it_prevents_absolute_paths_in_zip_entries() throws IOException {
    var entry = new ZipEntry("/foo.txt");
    var is = createZipFrom(entry);

    var hardenedStream = Zip.createHardenedZipInputStream(is);
    assertThrows(SecurityException.class, hardenedStream::getNextEntry);
  }

  private InputStream createZipFrom(final ZipEntry entry) throws IOException {
    var os = new ByteArrayOutputStream();
    var zos = new ZipOutputStream(os);
    zos.putNextEntry(entry);
    zos.closeEntry();
    zos.close();

    return new ByteArrayInputStream(os.toByteArray());
  }
}
