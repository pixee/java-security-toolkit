package pixee;

import java.io.File;
import java.util.*;
import java.util.Map;
import java.util.Vector;

/**
 * This code borrowed from Apache Commons Exec:
 *
 * <p>https://raw.githubusercontent.com/apache/commons-exec/master/src/main/java/org/apache/commons/exec/CommandLine.java
 *
 * <p>Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
final class CommandLine {

  /** The arguments of the command. */
  private final Vector<Argument> arguments = new Vector<>();

  /** The program to execute. */
  private final String executable;

  /** A map of name value pairs used to expand command line arguments */
  private Map<String, ?> substitutionMap; // N.B. This can contain values other than Strings

  /** Was a file being used to set the executable? */
  private final boolean isFile;

  /**
   * Create a command line from a string.
   *
   * @param line the first element becomes the executable, the rest the arguments
   * @return the parsed command line
   * @throws IllegalArgumentException If line is null or all whitespace
   */
  public static CommandLine parse(final String line) {
    return parse(line, null);
  }

  /**
   * Create a command line from a string.
   *
   * @param line the first element becomes the executable, the rest the arguments
   * @param substitutionMap the name/value pairs used for substitution
   * @return the parsed command line
   * @throws IllegalArgumentException If line is null or all whitespace
   */
  static CommandLine parse(final String line, final Map<String, ?> substitutionMap) {

    if (line == null) {
      throw new IllegalArgumentException("Command line can not be null");
    }
    if (line.trim().isEmpty()) {
      throw new IllegalArgumentException("Command line can not be empty");
    }
    final String[] tmp = translateCommandline(line);

    final CommandLine cl = new CommandLine(tmp[0]);
    cl.setSubstitutionMap(substitutionMap);
    for (int i = 1; i < tmp.length; i++) {
      cl.addArgument(tmp[i]);
    }

    return cl;
  }

  /**
   * Create a command line without any arguments.
   *
   * @param executable the executable
   */
  CommandLine(final String executable) {
    this.isFile = false;
    this.executable = toCleanExecutable(executable);
  }

  /**
   * Create a command line without any arguments.
   *
   * @param executable the executable file
   */
  CommandLine(final File executable) {
    this.isFile = true;
    this.executable = toCleanExecutable(executable.getAbsolutePath());
  }

  /**
   * Copy constructor.
   *
   * @param other the instance to copy
   */
  CommandLine(final CommandLine other) {
    this.executable = other.getExecutable();
    this.isFile = other.isFile();
    this.arguments.addAll(other.arguments);

    if (other.getSubstitutionMap() != null) {
      final Map<String, Object> omap = new HashMap<>();
      this.substitutionMap = omap;
      final Iterator<String> iterator = other.substitutionMap.keySet().iterator();
      while (iterator.hasNext()) {
        final String key = iterator.next();
        omap.put(key, other.getSubstitutionMap().get(key));
      }
    }
  }

  /**
   * Returns the executable.
   *
   * @return The executable
   */
  String getExecutable() {
    // Expand the executable and replace '/' and '\\' with the platform
    // specific file separator char. This is safe here since we know
    // that this is a platform specific command.
    return StringUtils.fixFileSeparatorChar(expandArgument(executable));
  }

  /**
   * Was a file being used to set the executable?
   *
   * @return true if a file was used for setting the executable
   */
  boolean isFile() {
    return isFile;
  }

  /**
   * Add multiple arguments. Handles parsing of quotes and whitespace.
   *
   * @param addArguments An array of arguments
   * @return The command line itself
   */
  CommandLine addArguments(final String[] addArguments) {
    return this.addArguments(addArguments, true);
  }

  /**
   * Add multiple arguments.
   *
   * @param addArguments An array of arguments
   * @param handleQuoting Add the argument with/without handling quoting
   * @return The command line itself
   */
  CommandLine addArguments(final String[] addArguments, final boolean handleQuoting) {
    if (addArguments != null) {
      for (final String addArgument : addArguments) {
        addArgument(addArgument, handleQuoting);
      }
    }

    return this;
  }

  /**
   * Add multiple arguments. Handles parsing of quotes and whitespace. Please note that the parsing
   * can have undesired side-effects therefore it is recommended to build the command line
   * incrementally.
   *
   * @param addArguments An string containing multiple arguments.
   * @return The command line itself
   */
  CommandLine addArguments(final String addArguments) {
    return this.addArguments(addArguments, true);
  }

  /**
   * Add multiple arguments. Handles parsing of quotes and whitespace. Please note that the parsing
   * can have undesired side-effects therefore it is recommended to build the command line
   * incrementally.
   *
   * @param addArguments An string containing multiple arguments.
   * @param handleQuoting Add the argument with/without handling quoting
   * @return The command line itself
   */
  CommandLine addArguments(final String addArguments, final boolean handleQuoting) {
    if (addArguments != null) {
      final String[] argumentsArray = translateCommandline(addArguments);
      addArguments(argumentsArray, handleQuoting);
    }

    return this;
  }

  /**
   * Add a single argument. Handles quoting.
   *
   * @param argument The argument to add
   * @return The command line itself
   * @throws IllegalArgumentException If argument contains both single and double quotes
   */
  CommandLine addArgument(final String argument) {
    return this.addArgument(argument, true);
  }

  /**
   * Add a single argument.
   *
   * @param argument The argument to add
   * @param handleQuoting Add the argument with/without handling quoting
   * @return The command line itself
   */
  CommandLine addArgument(final String argument, final boolean handleQuoting) {

    if (argument == null) {
      return this;
    }

    // check if we can really quote the argument - if not throw an
    // IllegalArgumentException
    if (handleQuoting) {
      StringUtils.quoteArgument(argument);
    }

    arguments.add(new Argument(argument, handleQuoting));
    return this;
  }

  /**
   * Returns the expanded and quoted command line arguments.
   *
   * @return The quoted arguments
   */
  String[] getArguments() {

    Argument currArgument;
    String expandedArgument;
    final String[] result = new String[arguments.size()];

    for (int i = 0; i < result.length; i++) {
      currArgument = arguments.get(i);
      expandedArgument = expandArgument(currArgument.getValue());
      result[i] =
          currArgument.isHandleQuoting()
              ? StringUtils.quoteArgument(expandedArgument)
              : expandedArgument;
    }

    return result;
  }

  /**
   * @return the substitution map
   */
  Map<String, ?> getSubstitutionMap() {
    return substitutionMap;
  }

  /**
   * Set the substitutionMap to expand variables in the command line.
   *
   * @param substitutionMap the map
   */
  void setSubstitutionMap(final Map<String, ?> substitutionMap) {
    this.substitutionMap = substitutionMap;
  }

  /**
   * Returns the command line as an array of strings.
   *
   * @return The command line as an string array
   */
  String[] toStrings() {
    final String[] result = new String[arguments.size() + 1];
    result[0] = this.getExecutable();
    System.arraycopy(getArguments(), 0, result, 1, result.length - 1);
    return result;
  }

  /**
   * Stringify operator returns the command line as a string. Parameters are correctly quoted when
   * containing a space or left untouched if the are already quoted.
   *
   * @return the command line as single string
   */
  @Override
  public String toString() {
    return "[" + StringUtils.toString(toStrings(), ", ") + "]";
  }

  // --- Implementation ---------------------------------------------------

  /**
   * Expand variables in a command line argument.
   *
   * @param argument the argument
   * @return the expanded string
   */
  private String expandArgument(final String argument) {
    final StringBuffer stringBuffer =
        StringUtils.stringSubstitution(argument, this.getSubstitutionMap(), true);
    return stringBuffer.toString();
  }

  /**
   * Crack a command line.
   *
   * @param toProcess the command line to process
   * @return the command line broken into strings. An empty or null toProcess parameter results in a
   *     zero sized array
   */
  private static String[] translateCommandline(final String toProcess) {
    if (toProcess == null || toProcess.isEmpty()) {
      // no command? no string
      return new String[0];
    }

    // parse with a simple finite state machine

    final int normal = 0;
    final int inQuote = 1;
    final int inDoubleQuote = 2;
    final int inComment = 3;
    int state = normal;
    final StringTokenizer tok = new StringTokenizer(toProcess, "\"\' ", true);
    final ArrayList<String> list = new ArrayList<>();
    StringBuilder current = new StringBuilder();
    boolean lastTokenHasBeenQuoted = false;

    while (tok.hasMoreTokens()) {
      final String nextTok = tok.nextToken();
      switch (state) {
        case inComment:
          break;
        case inQuote:
          if ("\'".equals(nextTok)) {
            lastTokenHasBeenQuoted = true;
            state = normal;
          } else {
            current.append(nextTok);
          }
          break;
        case inDoubleQuote:
          if ("\"".equals(nextTok)) {
            lastTokenHasBeenQuoted = true;
            state = normal;
          } else {
            current.append(nextTok);
          }
          break;
        default:
          if ("\'".equals(nextTok)) {
            state = inQuote;
          } else if ("\"".equals(nextTok)) {
            state = inDoubleQuote;
          } else if (" ".equals(nextTok)) {
            if (lastTokenHasBeenQuoted || current.length() != 0) {
              list.add(current.toString());
              current = new StringBuilder();
            }
          } else if ("#".equals(nextTok)) {
            state = inComment;
          } else {
            current.append(nextTok);
          }
          lastTokenHasBeenQuoted = false;
          break;
      }
    }

    if (lastTokenHasBeenQuoted || current.length() != 0) {
      list.add(current.toString());
    }

    if (state == inQuote || state == inDoubleQuote) {
      throw new IllegalArgumentException("Unbalanced quotes in " + toProcess);
    }

    final String[] args = new String[list.size()];
    return list.toArray(args);
  }

  /**
   * Cleans the executable string. The argument is trimmed and '/' and '\\' are replaced with the
   * platform specific file separator char
   *
   * @param dirtyExecutable the executable
   * @return the platform-specific executable string
   */
  private String toCleanExecutable(final String dirtyExecutable) {
    if (dirtyExecutable == null) {
      throw new IllegalArgumentException("Executable can not be null");
    }
    if (dirtyExecutable.trim().isEmpty()) {
      throw new IllegalArgumentException("Executable can not be empty");
    }
    return StringUtils.fixFileSeparatorChar(dirtyExecutable);
  }

  /** Encapsulates a command line argument. */
  static class Argument {

    private final String value;
    private final boolean handleQuoting;

    private Argument(final String value, final boolean handleQuoting) {
      this.value = value.trim();
      this.handleQuoting = handleQuoting;
    }

    private String getValue() {
      return value;
    }

    private boolean isHandleQuoting() {
      return handleQuoting;
    }
  }

  /** This class lifted from the same source. */
  private static class StringUtils {

    private static final String SINGLE_QUOTE = "\'";
    private static final String DOUBLE_QUOTE = "\"";
    private static final char SLASH_CHAR = '/';
    private static final char BACKSLASH_CHAR = '\\';

    /**
     * Perform a series of substitutions.
     *
     * <p>The substitutions are performed by replacing ${variable} in the target string with the
     * value of provided by the key "variable" in the provided hash table.
     *
     * <p>A key consists of the following characters:
     *
     * <ul>
     *   <li>letter
     *   <li>digit
     *   <li>dot character
     *   <li>hyphen character
     *   <li>plus character
     *   <li>underscore character
     * </ul>
     *
     * @param argStr the argument string to be processed
     * @param vars name/value pairs used for substitution
     * @param isLenient ignore a key not found in vars or throw a RuntimeException?
     * @return String target string with replacements.
     */
    static StringBuffer stringSubstitution(
        final String argStr, final Map<? super String, ?> vars, final boolean isLenient) {

      final StringBuffer argBuf = new StringBuffer();

      if (argStr == null || argStr.isEmpty()) {
        return argBuf;
      }

      if (vars == null || vars.isEmpty()) {
        return argBuf.append(argStr);
      }

      final int argStrLength = argStr.length();

      for (int cIdx = 0; cIdx < argStrLength; ) {

        char ch = argStr.charAt(cIdx);
        char del = ' ';

        switch (ch) {
          case '$':
            final StringBuilder nameBuf = new StringBuilder();
            del = argStr.charAt(cIdx + 1);
            if (del == '{') {
              cIdx++;

              for (++cIdx; cIdx < argStr.length(); ++cIdx) {
                ch = argStr.charAt(cIdx);
                if ((ch != '_')
                    && (ch != '.')
                    && (ch != '-')
                    && (ch != '+')
                    && !Character.isLetterOrDigit(ch)) {
                  break;
                }
                nameBuf.append(ch);
              }

              if (nameBuf.length() >= 0) {

                String value;
                final Object temp = vars.get(nameBuf.toString());

                if (temp instanceof File) {
                  // for a file we have to fix the separator chars to allow
                  // cross-platform compatibility
                  value = fixFileSeparatorChar(((File) temp).getAbsolutePath());
                } else {
                  value = temp != null ? temp.toString() : null;
                }

                if (value != null) {
                  argBuf.append(value);
                } else {
                  if (!isLenient) {
                    // complain that no variable was found
                    throw new RuntimeException("No value found for : " + nameBuf);
                  }
                  // just append the unresolved variable declaration
                  argBuf.append("${").append(nameBuf.toString()).append("}");
                }

                del = argStr.charAt(cIdx);

                if (del != '}') {
                  throw new RuntimeException("Delimiter not found for : " + nameBuf);
                }
              }

              cIdx++;
            } else {
              argBuf.append(ch);
              ++cIdx;
            }

            break;

          default:
            argBuf.append(ch);
            ++cIdx;
            break;
        }
      }

      return argBuf;
    }

    /**
     * Split a string into an array of strings based on a separator.
     *
     * @param input what to split
     * @param splitChar what to split on
     * @return the array of strings
     */
    static String[] split(final String input, final String splitChar) {
      final StringTokenizer tokens = new StringTokenizer(input, splitChar);
      final List<String> strList = new ArrayList<>();
      while (tokens.hasMoreTokens()) {
        strList.add(tokens.nextToken());
      }
      return strList.toArray(new String[strList.size()]);
    }

    /**
     * Fixes the file separator char for the target platform using the following replacement.
     *
     * <ul>
     *   <li>'/' &#x2192; File.separatorChar
     *   <li>'\\' &#x2192; File.separatorChar
     * </ul>
     *
     * @param arg the argument to fix
     * @return the transformed argument
     */
    static String fixFileSeparatorChar(final String arg) {
      return arg.replace(SLASH_CHAR, File.separatorChar)
          .replace(BACKSLASH_CHAR, File.separatorChar);
    }

    /**
     * Concatenates an array of string using a separator.
     *
     * @param strings the strings to concatenate
     * @param separator the separator between two strings
     * @return the concatenated strings
     */
    static String toString(final String[] strings, final String separator) {
      final StringBuilder sb = new StringBuilder();
      for (int i = 0; i < strings.length; i++) {
        if (i > 0) {
          sb.append(separator);
        }
        sb.append(strings[i]);
      }
      return sb.toString();
    }

    /**
     * Put quotes around the given String if necessary.
     *
     * <p>If the argument doesn't include spaces or quotes, return it as is. If it contains double
     * quotes, use single quotes - else surround the argument by double quotes.
     *
     * @param argument the argument to be quoted
     * @return the quoted argument
     * @throws IllegalArgumentException If argument contains both types of quotes
     */
    static String quoteArgument(final String argument) {

      String cleanedArgument = argument.trim();

      // strip the quotes from both ends
      while (cleanedArgument.startsWith(SINGLE_QUOTE) || cleanedArgument.startsWith(DOUBLE_QUOTE)) {
        cleanedArgument = cleanedArgument.substring(1);
      }

      while (cleanedArgument.endsWith(SINGLE_QUOTE) || cleanedArgument.endsWith(DOUBLE_QUOTE)) {
        cleanedArgument = cleanedArgument.substring(0, cleanedArgument.length() - 1);
      }

      final StringBuilder buf = new StringBuilder();
      if (cleanedArgument.indexOf(DOUBLE_QUOTE) > -1) {
        if (cleanedArgument.indexOf(SINGLE_QUOTE) > -1) {
          throw new IllegalArgumentException(
              "Can't handle single and double quotes in same argument");
        }
        return buf.append(SINGLE_QUOTE).append(cleanedArgument).append(SINGLE_QUOTE).toString();
      }
      if (cleanedArgument.indexOf(SINGLE_QUOTE) > -1 || cleanedArgument.indexOf(" ") > -1) {
        return buf.append(DOUBLE_QUOTE).append(cleanedArgument).append(DOUBLE_QUOTE).toString();
      }
      return cleanedArgument;
    }

    /**
     * Determines if this is a quoted argument - either single or double quoted.
     *
     * @param argument the argument to check
     * @return true when the argument is quoted
     */
    static boolean isQuoted(final String argument) {
      return argument.startsWith(SINGLE_QUOTE) && argument.endsWith(SINGLE_QUOTE)
          || argument.startsWith(DOUBLE_QUOTE) && argument.endsWith(DOUBLE_QUOTE);
    }
  }
}
