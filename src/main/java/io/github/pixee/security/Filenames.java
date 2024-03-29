package io.github.pixee.security;

import java.io.File;

/** This type offers utilities to safely deal with filenames. */
public final class Filenames {

  private Filenames() {}

  /**
   * Take an arbitrary file path (full, relative, or a simple name) and return a guaranteed simple
   * name without any directory. For instance:
   *
   * <table>
   *     <caption>the inputs and outputs of the API showing all the directory elements of the paths taken out</caption>
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
   * @param fileName the file name to normalize
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
    if (fileName == null || "".equals(fileName.trim())) {
      // this file name may cause issues with the apis they'll be used in but we can't help so don't
      // try
      return fileName;
    }
    return new File(fileName)
        .getName()
        .replace("" + (char) 0x0, "")
        .replace("/", "")
        .replace(":", "")
        .replace("\\", "");
  }
}
