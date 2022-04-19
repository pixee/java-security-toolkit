package pixee;

import com.coverity.security.Escape;

/**
 * This type exposes helper methods that will help defend against XSS attacks.
 *
 * <p>For more information on XSS:
 * https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
 */
public final class XSS {

  private XSS() {}

  /**
   * Return an HTML-encoded version of the value passed in.
   *
   * @return an HTML-encoded version of the String passed in, or null if the input was null
   */
  public static String htmlEncode(final String s) {
    return Escape.html(s);
  }
}
