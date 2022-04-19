package pixee;

/** This type exposes helper methods that will help defend against header injection attacks. */
public final class HttpHeader {

  private HttpHeader() {}

  /** Removes newlines from the given string, if any exist. */
  public static String stripNewlines(final String headerValue) {
    if (headerValue == null) {
      return null;
    }
    return headerValue.replace("\r", "").replace("\n", "");
  }
}
