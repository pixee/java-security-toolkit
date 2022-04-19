package io.pixee.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.beans.XMLDecoder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class SafeIOTest {

  @Test
  void doesnt_read_more_than_specified() {
    Reader br = new BufferedReader(new StringReader("123\n456"));
    assertThrows(SecurityException.class, () -> SafeIO.boundedReadLine(br, 2));
  }

  @Test
  void two_readlines_work() throws IOException {
    BufferedReader br = new BufferedReader(new StringReader("123\n456"));
    assertThat(SafeIO.boundedReadLine(br, 3), equalTo("123"));
    assertThat(SafeIO.boundedReadLine(br, 3), equalTo("456"));

    br = new BufferedReader(new StringReader("12"));
    assertThat(SafeIO.boundedReadLine(br, 2), equalTo("12"));
  }

  @Test
  void it_protects_xmldecoder() {

    // this just confirms that we can read basic objects
    {
      String mapXml =
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
              + "<java version=\"1.8.0\" class=\"java.beans.XMLDecoder\">\n"
              + " <object class=\"java.util.HashMap\">\n"
              + "  <void method=\"put\">\n"
              + "   <string>array</string>\n"
              + "   <object class=\"java.util.ArrayList\"/>\n"
              + "  </void>\n"
              + "  <void method=\"put\">\n"
              + "   <string>name</string>\n"
              + "   <string>test</string>\n"
              + "  </void>\n"
              + " </object>\n"
              + "</java>";
      XMLDecoder decoder = new XMLDecoder(getInputStreamFor(mapXml));
      Map map = (Map) decoder.readObject();
      assertThat(map.get("name"), equalTo("test"));

      // run it again with our protection on to ensure it doesn't break anything
      decoder = new XMLDecoder(SafeIO.toSafeXmlDecoderInputStream(getInputStreamFor(mapXml)));
      map = (Map) decoder.readObject();
      assertThat(map.get("name"), equalTo("test"));
    }

    // now we'll test that an attack can produce a ProcessBuilder (but we won't execute anythingw
    // ith it)
    {
      String processBuilderXml =
          "<java version=\"1.7.0_80\" class=\"java.beans.XMLDecoder\">\n"
              + " <object class=\"java.lang.ProcessBuilder\">\n"
              + "  <array class=\"java.lang.String\" length=\"1\">\n"
              + "    <void index=\"0\"><string>calc</string></void>\n"
              + "  </array>\n"
              + "  <!--<void method=\"start\"></void>--> uncommenting this will cause it to run\n"
              + " </object>\n"
              + "</java>";
      XMLDecoder decoder = new XMLDecoder(getInputStreamFor(processBuilderXml));
      ProcessBuilder pb = (ProcessBuilder) decoder.readObject();
      assertThat(pb.command().size(), equalTo(1));
      assertThat(pb.command().get(0), equalTo("calc"));

      // now we'll run it again, but with our protective InputStream
      final XMLDecoder protectedDecoder =
          new XMLDecoder(SafeIO.toSafeXmlDecoderInputStream(getInputStreamFor(processBuilderXml)));
      assertThrows(SecurityException.class, () -> protectedDecoder.readObject());
    }
  }

  private ByteArrayInputStream getInputStreamFor(String processBuilderXml) {
    return new ByteArrayInputStream(processBuilderXml.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ValueSource(strings = {"../foo.txt", "foo.txt", "/whatever/foo.txt"})
  void it_normalizes_paths(final String path) {
    assertThat(SafeIO.toSimpleFileName(path), equalTo("foo.txt"));
  }

  @Test
  void it_normalizes_windows_path_safely() {
    assertThat(SafeIO.toSimpleFileName("C:\\windows\\foo.txt"), equalTo("Cwindowsfoo.txt"));
  }
}
