package io.openpixee.security;

import java.io.IOException;
import java.io.Reader;
import java.util.Objects;

/** This type exposes helper methods to deal with protecting I/O operations. */
public final class BoundedLineReader {

  private BoundedLineReader() {}

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

  private static String readLine(final ReaderWrapper in, final int max) throws IOException {
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
  public static String readLine(final Reader reader, final int max) throws IOException {
    return readLine(new BufferedReaderWrapper(reader), max);
  }
}
