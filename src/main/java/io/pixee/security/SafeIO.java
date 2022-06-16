package io.pixee.security;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.commons.io.input.buffer.CircularByteBuffer;

/** This type exposes helper methods to deal with protecting I/O operations. */
public final class SafeIO {

  private SafeIO() {}

  private interface ReaderWrapper {
    int read() throws IOException;
  }

  private static class BufferedReaderWrapper implements ReaderWrapper {

    private final Reader bufferedReader;

    private BufferedReaderWrapper(final Reader bufferedReader) {
      this.bufferedReader = Objects.requireNonNull(bufferedReader);
    }

    @Override
    public int read() throws IOException {
      return bufferedReader.read();
    }
  }

  private static String boundedReadLine(final ReaderWrapper in, final int max) throws IOException {
    if (max <= 0) {
      throw new IllegalArgumentException("must read a positive number of bytes from the stream");
    }

    StringBuilder sb = new StringBuilder();
    int count = 0;
    int c;

    while (true) {
      c = in.read();
      if (c == -1) {
        if (sb.length() == 0) {
          return null;
        }
        break;
      }
      if (c == '\n' || c == '\r') {
        break;
      }
      count++;
      if (count > max) {
        throw new SecurityException("read more than maximum characters allowed (" + max + ")");
      }
      sb.append((char) c);
    }
    return sb.toString();
  }

  /**
   * This method reads until a newline is encountered or the specified number of characters is
   * reached.
   *
   * <p>This code originally came from the OWASP ESAPI project:
   *
   * @see <a
   *     href="https://wiki.sei.cmu.edu/confluence/display/java/MSC05-J.+Do+not+exhaust+heap+space">https://wiki.sei.cmu.edu/confluence/display/java/MSC05-J.+Do+not+exhaust+heap+space</a>
   * @see <a
   *     href="https://github.com/vishank848/owasp-esapi-java/blob/master/src/main/java/org/owasp/esapi/reference/DefaultValidator.java">https://github.com/vishank848/owasp-esapi-java/blob/master/src/main/java/org/owasp/esapi/reference/DefaultValidator.java</a>
   */
  public static String boundedReadLine(final Reader reader, final int max) throws IOException {
    return boundedReadLine(new BufferedReaderWrapper(reader), max);
  }

  /**
   * This method wraps an {@link InputStream} with a circular byte buffer that watches for tokens.
   * It will harm the performance of the operation if I/O is extremely fast.
   */
  public static InputStream tokenDetectingInputStream(
      final InputStream is, final List<String> wordsToWatch) {
    final List<byte[]> byteStreamsToWatch =
        wordsToWatch.stream()
            .map(word -> word.getBytes(StandardCharsets.UTF_8))
            .collect(Collectors.toUnmodifiableList());
    return new TokenDetectingInputStream(is, byteStreamsToWatch);
  }

  /**
   * This method wraps the stream in a circular byte buffer which looks for common exploit types in
   * the inbound XML. This is far from a complete protection. There are an infinite number of ways
   * you could turn arbitrary code execution into meaningful exploitation. However, we provide some
   * best effort signaturing here as it may prevent common attack payloads from being successful.
   *
   * <p>There is no substitute for just _not_ using {@link java.beans.XMLDecoder} as it is unsafe --
   * even more unsafe than Java deserialization. Please consider using a serializer which is less
   * featured on the "transformation" front like Jackson, Gson, etc.
   *
   * @see <a
   *     href="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html">https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html</a>
   * @see <a
   *     href="https://github.com/o2platform/DefCon_RESTing/blob/master/Demos/_O2_Scripts/XmlEncoder%20-%20Restlet/exploits/7a%20-%20Creating%20a%20File.xml">https://github.com/o2platform/DefCon_RESTing/blob/master/Demos/_O2_Scripts/XmlEncoder%20-%20Restlet/exploits/7a%20-%20Creating%20a%20File.xml</a>
   */
  public static InputStream toSafeXmlDecoderInputStream(final InputStream is) {
    return tokenDetectingInputStream(
        is, List.of("java.lang.Runtime", "java.lang.ProcessBuilder", "java.io.FileOutputStream"));
  }

  private static class TokenDetectingInputStream extends InputStream {

    private final InputStream is;
    private final List<byte[]> tokensToWatch;
    private final CircularByteBuffer circularByteBuffer;

    private TokenDetectingInputStream(final InputStream is, final List<byte[]> tokensToWatch) {
      this.is = Objects.requireNonNull(is);
      if (tokensToWatch.size() == 0) {
        throw new IllegalArgumentException("need some tokens to watch");
      }
      this.tokensToWatch = tokensToWatch;
      int maxLength = 0;
      for (byte[] token : tokensToWatch) {
        if (token == null || token.length == 0) {
          throw new IllegalArgumentException("can't have null / zero sized token");
        }
        if (token.length > maxLength) {
          maxLength = token.length;
        }
      }
      circularByteBuffer = new CircularByteBuffer(maxLength);
    }

    @Override
    public int read() throws IOException {
      int read = is.read();
      // add the byte to the list
      circularByteBuffer.add((byte) read);

      for (byte[] token : tokensToWatch) {
        if (circularByteBuffer.peek(token, 0, token.length)) {
          throw new SecurityException("encountered token");
        }
      }

      // free space if needed
      if (!circularByteBuffer.hasSpace()) {
        circularByteBuffer.read();
      }
      return read;
    }
  }

  /**
   * Take an arbitrary file path (full, relative, or a simple name) and return a guaranteed simple
   * name without any directory. For instance:
   *
   * <table>
   *     <tr>
   *         <th>Input</th>
   *         <th>Output</th>
   *     </tr>
   *     <tr>
   *         <td>../whatever/foo.txt</td>
   *         <td>foo.txt</td>
   *     </tr>
   *     <tr>
   *         <td>C:\foo.txt</td>
   *         <td>foo.txt</td>
   *     </tr>
   *     <tr>
   *         <td>foo.txt</td>
   *         <td>foo.txt</td>
   *     </tr>
   * </table>
   *
   * @return a directoryless version of a file name
   * @see <a
   *     href="https://github.com/spring-projects/spring-framework/blob/main/spring-web/src/main/java/org/springframework/web/multipart/MultipartFile.java">Spring
   *     Multipart warning</a>
   * @see <a href="https://tools.ietf.org/html/rfc7578#section-4.2">RFC 7578, Section 4.2</a>
   * @see <a
   *     href="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload">Unrestricted
   *     File Upload</a>
   */
  public static String toSimpleFileName(final String fileName) {
    if (fileName == null || fileName.isBlank()) {
      // this file name will probably cause issues but we can't help
      return fileName;
    }
    return new File(fileName).getName().replace("" + (char)0x0, "").replace("/", "").replace(":", "").replace("\\", "");
  }
}
