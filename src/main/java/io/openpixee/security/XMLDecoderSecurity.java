package io.openpixee.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.commons.io.input.buffer.CircularByteBuffer;

/** This type offers APIs to help secure the usage of {@link java.beans.XMLDecoder}. */
public final class XMLDecoderSecurity {

  private XMLDecoderSecurity() {}

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
   * @param is the stream which we want to wrap with a token-detecting protect
   *
   * @see <a
   *     href="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html">https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html</a>
   * @see <a
   *     href="https://github.com/o2platform/DefCon_RESTing/blob/master/Demos/_O2_Scripts/XmlEncoder%20-%20Restlet/exploits/7a%20-%20Creating%20a%20File.xml">https://github.com/o2platform/DefCon_RESTing/blob/master/Demos/_O2_Scripts/XmlEncoder%20-%20Restlet/exploits/7a%20-%20Creating%20a%20File.xml</a>
   */
  public static InputStream hardenStream(final InputStream is) {
    return tokenDetectingInputStream(
        is, List.of("java.lang.Runtime", "java.lang.ProcessBuilder", "java.io.FileOutputStream"));
  }

  /**
   * This method wraps an {@link InputStream} with a circular byte buffer that watches for tokens.
   * It will harm the performance of the operation if I/O is extremely fast.
   */
  private static InputStream tokenDetectingInputStream(
      final InputStream is, final List<String> wordsToWatch) {
    final List<byte[]> byteStreamsToWatch =
        wordsToWatch.stream()
            .map(word -> word.getBytes(StandardCharsets.UTF_8))
            .collect(Collectors.toUnmodifiableList());
    return new TokenDetectingInputStream(is, byteStreamsToWatch);
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
}
