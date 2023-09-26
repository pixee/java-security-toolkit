package io.github.pixee.security;

/**
 * This type exposes helper methods that will help defend against XSS attacks with HTML encoding.
 *
 * <p>For more information on XSS:
 * https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
 */
public final class HtmlEncoder {

  private HtmlEncoder() {}

  /**
   * Return an HTML-encoded version of the value passed in.
   *
   * @param s the string in which to replace HTML entities
   * @return an HTML-encoded version of the String passed in, or null if the input was null
   */
  public static String encode(final String s) {
    return Escape.html(s);
  }

  /*
   * This code was originally brought in as the BSD-2 licensed dependency from Coverity. However, it didn't publish any automatic module name, and we didn't really need any of the rest of it, so we just copied the code here, including the license.
   */

  /**
   * Copyright (c) 2012-2016, Coverity, Inc. All rights reserved.
   *
   * <p>Redistribution and use in source and binary forms, with or without modification, are
   * permitted provided that the following conditions are met: - Redistributions of source code must
   * retain the above copyright notice, this list of conditions and the following disclaimer. -
   * Redistributions in binary form must reproduce the above copyright notice, this list of
   * conditions and the following disclaimer in the documentation and/or other materials provided
   * with the distribution. - Neither the name of Coverity, Inc. nor the names of its contributors
   * may be used to endorse or promote products derived from this software without specific prior
   * written permission from Coverity, Inc.
   *
   * <p>THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
   * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND INFRINGEMENT ARE DISCLAIMED. IN NO EVENT
   * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
   * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */
  /**
   * Escape is a small set of methods for escaping tainted data. These escaping methods are useful
   * in transforming user-controlled ("tainted") data into forms that are safe from being
   * interpreted as something other than data, such as JavaScript.
   *
   * <p>At this time most of these escaping routines focus on cross-site scripting mitigations. Each
   * method is good for a different HTML context. For a primer on HTML contexts, see OWASP's XSS
   * Prevention Cheat Sheet (note however that the escaping routines are not implemented exactly
   * according to OWASP's recommendations) or the Coverity Security Advisor documentation. Also see
   * the Coverity Security Research Laboratory blog on how to properly use each function.
   *
   * <p>While Coverity's static analysis product references these escaping routines as exemplars and
   * understands their behavior, there is no dependency on Coverity products and these routines are
   * completely standalone. Feel free to use them! Just make sure you use them correctly.
   *
   * @author Romain Gaucher
   * @author Andy Chou
   * @author Jon Passki
   * @author Alex Kouzemtchenko
   */
  private static class Escape {

    /**
     * HTML entity escaping for text content and attributes.
     *
     * <p>HTML entity escaping that is appropriate for the most common HTML contexts: PCDATA and
     * "normal" attributes (non-URI, non-event, and non-CSS attributes). <br>
     * Note that we do not recommend using non-quoted HTML attributes since the security obligations
     * vary more between web browser. We recommend to always quote (single or double quotes) HTML
     * attributes.<br>
     * This method is generic to HTML entity escaping, and therefore escapes more characters than
     * usually necessary -- mostly to handle non-quoted attribute values. If this method is somehow
     * too slow, such as you output megabytes of text with spaces, please use the {@link
     * #htmlText(String)} method which only escape HTML text specific characters.
     *
     * <p>The following characters are escaped:
     *
     * <ul>
     *   <li>HTML characters: <code>' (U+0022)</code>, <code>" (U+0027)</code>, <code>\ (U+005C)
     *       </code>, <code>/ (U+002F)</code>, <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)
     *       </code>, <code>&amp; (U+0026)</code>
     *   <li>Control characters: <code>\t (U+0009)</code>, <code>\n (U+000A)</code>, <code>
     *       \f (U+000C)</code>, <code>\r (U+000D)</code>, <code>SPACE (U+0020)</code>
     *   <li>Unicode newlines: <code>LS (U+2028)</code>, <code>PS (U+2029)</code>
     * </ul>
     *
     * @param input the string to be escaped
     * @return the HTML escaped string or <code>null</code> if <code>input</code> is null
     * @since 1.0
     */
    private static String html(String input) {
      if (input == null) return null;

      int length = input.length();
      StringBuilder output = allocateStringBuilder(length);

      for (int i = 0; i < length; i++) {
        char c = input.charAt(i);
        switch (c) {
            // Control chars
          case '\t':
            output.append("&#x09;");
            break;
          case '\n':
            output.append("&#x0A;");
            break;
          case '\f':
            output.append("&#x0C;");
            break;
          case '\r':
            output.append("&#x0D;");
            break;
            // Chars that have a meaning for HTML
          case '\'':
            output.append("&#39;");
            break;
          case '\\':
            output.append("&#x5C;");
            break;
          case ' ':
            output.append("&#x20;");
            break;
          case '/':
            output.append("&#x2F;");
            break;
          case '"':
            output.append("&quot;");
            break;
          case '<':
            output.append("&lt;");
            break;
          case '>':
            output.append("&gt;");
            break;
          case '&':
            output.append("&amp;");
            break;
            // Unicode new lines
          case '\u2028':
            output.append("&#x2028;");
            break;
          case '\u2029':
            output.append("&#x2029;");
            break;

          default:
            output.append(c);
            break;
        }
      }
      return output.toString();
    }

    /**
     * URI encoder.
     *
     * <p>URI encoding for query string values of the URI: <code>
     * /example/?name=URI_ENCODED_VALUE_HERE</code> <br>
     * Note that this method is not sufficient to protect for cross-site scripting in a generic URI
     * context, but only for query string values. If you need to escape a URI in an <code>href
     * </code> attribute (for example), ensure that:
     *
     * <ul>
     *   <li>The scheme is allowed (restrict to http, https, or mailto)
     *   <li>Use the HTML escaper {@link #html(String)} on the entire URI
     * </ul>
     *
     * This URI encoder processes the following characters:
     *
     * <ul>
     *   <li>URI characters: <code>' (U+0022)</code>, <code>" (U+0027)</code>, <code>\ (U+005C)
     *       </code>, <code>/ (U+002F)</code>, <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)
     *       </code>, <code>&amp; (U+0026)</code>, <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)
     *       </code>, <code>! (U+0021)</code>, <code># (U+0023)</code>, <code>$ (U+0024)</code>,
     *       <code>% (U+0025)</code>, <code>( (U+0028)</code>, <code>) (U+0029)</code>, <code>
     *       * (U+002A)</code>, <code>+ (U+002B)</code>, <code>, (U+002C)</code>, <code>. (U+002E)
     *       </code>, <code>: (U+003A)</code>, <code>; (U+003B)</code>, <code>= (U+003D)</code>,
     *       <code>? (U+003F)</code>, <code>@ (U+0040)</code>, <code>[ (U+005B)</code>, <code>
     *       ] (U+005D)</code>
     *   <li>Control characters: <code>\t (U+0009)</code>, <code>\n (U+000A)</code>, <code>
     *       \f (U+000C)</code>, <code>\r (U+000D)</code>, <code>SPACE (U+0020)</code>
     * </ul>
     *
     * @param input the string to be escaped
     * @return the URI encoded string or <code>null</code> if <code>input</code> is null
     * @since 1.0
     */
    private static String uriParam(String input) {
      if (input == null) return null;

      int length = input.length();
      StringBuilder output = allocateStringBuilder(length);

      for (int i = 0; i < length; i++) {
        char c = input.charAt(i);
        switch (c) {
            // Control chars
          case '\t':
            output.append("%09");
            break;
          case '\n':
            output.append("%0A");
            break;
          case '\f':
            output.append("%0C");
            break;
          case '\r':
            output.append("%0D");
            break;
            // RFC chars to encode, plus % ' " < and >, and space
          case ' ':
            output.append("%20");
            break;
          case '!':
            output.append("%21");
            break;
          case '"':
            output.append("%22");
            break;
          case '#':
            output.append("%23");
            break;
          case '$':
            output.append("%24");
            break;
          case '%':
            output.append("%25");
            break;
          case '&':
            output.append("%26");
            break;
          case '\'':
            output.append("%27");
            break;
          case '(':
            output.append("%28");
            break;
          case ')':
            output.append("%29");
            break;
          case '*':
            output.append("%2A");
            break;
          case '+':
            output.append("%2B");
            break;
          case ',':
            output.append("%2C");
            break;
          case '.':
            output.append("%2E");
            break;
          case '/':
            output.append("%2F");
            break;
          case ':':
            output.append("%3A");
            break;
          case ';':
            output.append("%3B");
            break;
          case '<':
            output.append("%3C");
            break;
          case '=':
            output.append("%3D");
            break;
          case '>':
            output.append("%3E");
            break;
          case '?':
            output.append("%3F");
            break;
          case '@':
            output.append("%40");
            break;
          case '[':
            output.append("%5B");
            break;
          case ']':
            output.append("%5D");
            break;

          default:
            output.append(c);
            break;
        }
      }
      return output.toString();
    }

    /** Compute the allocation size of the StringBuilder based on the length. */
    private static StringBuilder allocateStringBuilder(int length) {
      // Allocate enough temporary buffer space to avoid reallocation in most
      // cases. If you believe you will output large amount of data at once
      // you might need to change the factor.
      int buflen = length;
      if (length * 2 > 0) buflen = length * 2;
      return new StringBuilder(buflen);
    }
  }
}
