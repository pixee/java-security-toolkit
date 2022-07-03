package io.pixee.security;

import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/** This type offers utility methods to run system commands more safely. */
public final class SystemCommand {

  private SystemCommand() {}

  /** The default restrictions if none are specified. */
  public static Set<SystemCommandRestrictions> defaultRestrictions() {
    return Set.of(
        SystemCommandRestrictions.PREVENT_COMMAND_CHAINING,
        SystemCommandRestrictions.PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES);
  }

  /**
   * Does the same as {@link Runtime#exec(String)}, but adds restrictions on what types of commands
   * will be allowed. Will throw a {@link SecurityException} if any of the restrictions may be
   * violated by the command found. Note that the method of detecting violations is based on
   * semantic analysis of the command, and so is vulnerable to impedance mismatches between the
   * analysis we perform and whatever shell is interpreting the command. Either way, it's a lot
   * safer.
   *
   * @param command the system command about to be run
   * @param runtime the runtime to run with
   * @param restrictions the set of restrictions to run with
   * @throws SecurityException if multiple commands are found
   * @throws IllegalArgumentException if restriction is null
   */
  public static Process runCommand(
      final Runtime runtime,
      final String command,
      final Set<SystemCommandRestrictions> restrictions)
      throws IOException {
    runChecks(command, restrictions);
    return runtime.exec(command);
  }

  /**
   * Delegates to {@link SystemCommand#runCommand(Runtime, String, Set)} with default restrictions.
   */
  public static Process runCommand(final Runtime runtime, final String command) throws IOException {
    return runCommand(runtime, command, defaultRestrictions());
  }

  /**
   * Does the same as {@link Runtime#exec(String[])}, but adds restrictions on what types of
   * commands will be allowed. Will throw a {@link SecurityException} if any of the restrictions may
   * be violated by the command found. Note that the method of detecting violations is based on
   * semantic analysis of the command, and so is vulnerable to impedance mismatches between the
   * analysis we perform and whatever shell is interpreting the command. Either way, it's a lot
   * safer.
   *
   * @param command the system command about to be run
   * @param runtime the runtime to run with
   * @param restrictions the set of restrictions to run with
   * @throws SecurityException if multiple commands are found
   * @throws IllegalArgumentException if restriction is null
   */
  public static Process runCommand(
      final Runtime runtime,
      final String[] command,
      final Set<SystemCommandRestrictions> restrictions)
      throws IOException {
    runChecks(command, restrictions);
    return runtime.exec(command);
  }

  /**
   * Delegates to {@link SystemCommand#runCommand(Runtime, String[], Set)} with default
   * restrictions.
   */
  public static Process runCommand(final Runtime runtime, final String[] command)
      throws IOException {
    return runCommand(runtime, command, defaultRestrictions());
  }

  /**
   * Same as {@link SystemCommand#runCommand(Runtime, String[], Set)} but also include more data to
   * pass into {@link Runtime#exec(String[], String[])}.
   */
  public static Process runCommand(
      final Runtime runtime,
      final String[] command,
      final String[] envp,
      final Set<SystemCommandRestrictions> restrictions)
      throws IOException {
    runChecks(command, restrictions);
    return runtime.exec(command, envp);
  }

  /**
   * Delegates to {@link SystemCommand#runCommand(Runtime, String[], String[], Set)} with default
   * restrictions.
   */
  public static Process runCommand(
      final Runtime runtime, final String[] command, final String[] envp) throws IOException {
    return runCommand(runtime, command, envp, defaultRestrictions());
  }

  /**
   * Same as {@link SystemCommand#runCommand(Runtime, String[], Set)} but also include more data to
   * pass into {@link Runtime#exec(String[], String[], File)}.
   */
  public static Process runCommand(
      final Runtime runtime,
      final String[] command,
      final String[] envp,
      final File dir,
      final Set<SystemCommandRestrictions> restrictions)
      throws IOException {
    runChecks(command, restrictions);
    return runtime.exec(command, envp, dir);
  }

  /**
   * Same as {@link SystemCommand#runCommand(Runtime, String, Set)} but also include more data to
   * pass into {@link Runtime#exec(String, String[])}.
   */
  public static Process runCommand(
      final Runtime runtime,
      final String command,
      final String[] envp,
      final Set<SystemCommandRestrictions> restrictions)
      throws IOException {
    runChecks(command, restrictions);
    return runtime.exec(command, envp);
  }

  /**
   * Delegates to {@link SystemCommand#runCommand(Runtime, String, String[], Set)} with default
   * restrictions.
   */
  public static Process runCommand(final Runtime runtime, final String command, final String[] envp)
      throws IOException {
    return runCommand(runtime, command, envp, defaultRestrictions());
  }

  /**
   * Same as {@link SystemCommand#runCommand(Runtime, String, Set)} but also include more data to
   * pass into {@link Runtime#exec(String, String[], File)}.
   */
  public static Process runCommand(
      final Runtime runtime,
      final String command,
      final String[] envp,
      final File dir,
      final Set<SystemCommandRestrictions> restrictions)
      throws IOException {
    runChecks(command, restrictions);
    return runtime.exec(command, envp, dir);
  }

  /**
   * Delegates to {@link SystemCommand#runCommand(Runtime, String, String[], File, Set)} with
   * default restrictions.
   */
  public static Process runCommand(
      final Runtime runtime, final String command, final String[] envp, final File dir)
      throws IOException {
    return runCommand(runtime, command, envp, dir, defaultRestrictions());
  }

  /**
   * Delegates to {@link SystemCommand#runCommand(Runtime, String[], String[], File, Set)} with
   * default restrictions.
   */
  public static Process runCommand(
      final Runtime runtime, final String[] command, final String[] envp, final File dir)
      throws IOException {
    return runCommand(runtime, command, envp, dir, defaultRestrictions());
  }

  private static void runChecks(
      final String command, final Set<SystemCommandRestrictions> restrictions) {
    /*
     * Our command parsing library blows up if it sees empty strings, so since we know it's safe, we
     * default to our principle of "let the app do what it normally would have done" and let Runtime#exec()
     * do whatever it wants to do with an empty string.
     */
    if (!command.trim().isEmpty()) {
      final CommandLine parsedCommandLine = CommandLine.parse(command);
      runChecks(parsedCommandLine, restrictions);
    }
  }

  private static void runChecks(
      final String[] command, final Set<SystemCommandRestrictions> restrictions) {
    final CommandLine parsedCommandLine = new CommandLine(command[0]);
    for (int i = 1; i < command.length; i++) {
      parsedCommandLine.addArgument(command[i]);
    }
    runChecks(parsedCommandLine, restrictions);
  }

  /**
   * This method is where all the check logic shoud be so we can have a bunch of smaller methods
   * reflecting the different signatures of {@link Runtime#exec(String)}.
   */
  private static void runChecks(
      final CommandLine parsedCommandLine, final Set<SystemCommandRestrictions> restrictions) {
    if (restrictions == null) {
      throw new IllegalArgumentException("restrictions must not be null");
    }

    if (restrictions.contains(SystemCommandRestrictions.PREVENT_COMMAND_CHAINING)) {
      if (isShell(parsedCommandLine.getExecutable())) {
        checkForMultipleCommands(parsedCommandLine.getArguments());
      }
    }

    if (restrictions.contains(SystemCommandRestrictions.PREVENT_COMMON_EXPLOIT_EXECUTABLES)) {
      checkForBannedExecutable(parsedCommandLine);
    }

    if (restrictions.contains(
        SystemCommandRestrictions.PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES)) {
      checkForSensitiveFileArguments(parsedCommandLine);
    }
  }

  private static void checkForBannedExecutable(final CommandLine commandLine) {
    final String executable = commandLine.getExecutable();
    try {
      File file = new File(executable).getCanonicalFile();
      String name = file.getName().trim();
      if (BANNED_EXECUTABLES.contains(name)) {
        throw new SecurityException("file inaccessible");
      }
    } catch (IOException e) {
      // probably not a file -- this is unexpected, but don't have enough evidence to throw anything
    }
  }

  private static void checkForSensitiveFileArguments(final CommandLine commandLine) {
    final String[] arguments = commandLine.getArguments();
    for (String argument : arguments) {
      try {
        File file = new File(argument).getCanonicalFile();
        String name = file.getAbsolutePath().trim();
        /*
         * On macOS this "ask the filesystem to canonicalize it for us" trick may resolve to files residing in
         * /private/whatever/ so we have to do an "ends with" check. This is fine, since it accomplishes the
         * same behavior.
         */
        for (String sensitiveFileName : SENSITIVE_FILE_NAMES) {
          if (name.endsWith(sensitiveFileName)) {
            throw new SecurityException("file inaccessible");
          }
        }
      } catch (IOException e) {
        // probably not a file -- this is expected
      }
    }
  }

  private static void checkForMultipleCommands(final String[] commandTokens) {
    int indexOfCommand = getCommandIndex(commandTokens);
    if (indexOfCommand != -1 && commandTokens.length > indexOfCommand) {
      String innerCommand = commandTokens[indexOfCommand];
      String trimmedCommand = innerCommand.trim();
      if (trimmedCommand.startsWith("\"") && trimmedCommand.endsWith("\"")) {
        trimmedCommand = trimmedCommand.substring(1, trimmedCommand.length() - 1);
      }
      int index = findCommandSeparator(trimmedCommand);
      if (index == -1) {
        throw new SecurityException("multiple commands not allowed");
      }
    }
  }

  /** Command line parsing context. */
  enum CommandParsingContext {
    DEFAULT,
    SINGLE_QUOTE,
    DOUBLE_QUOTE,
    COMMENT
  }

  private static int findCommandSeparator(final String command) {
    var context = new LinkedList<CommandParsingContext>();
    var i = 0;
    context.push(CommandParsingContext.DEFAULT);
    while (i < command.length()) {
      var currentContext = context.peek();
      switch (currentContext) {
        case DOUBLE_QUOTE:
          i = eatUntilNextDoubleQuote(command, i);
          context.pop();
          break;
        case SINGLE_QUOTE:
          i = eatUntilNextSingleQuote(command, i);
          context.pop();
          break;
        case COMMENT:
          i = eatUntilNextNewline(command, i);
          context.pop();
        case DEFAULT:
          char ch = command.charAt(i);
          switch (ch) {
              // we don't attempt to notice stdout/stderr redirection -- should we?
            case '\"':
              context.push(CommandParsingContext.DOUBLE_QUOTE);
              i++;
              break;
            case '\'':
              context.push(CommandParsingContext.SINGLE_QUOTE);
              i++;
              break;
            case ';':
            case '&':
            case '|':
              return i;
            default:
              i++;
          }
        default:
          // how'd we get here?
          return -1;
      }
    }
    return -1;
  }

  private static int eatUntilNextDoubleQuote(final String command, final int offset) {
    return eatUntilChar(command, offset, '\"');
  }

  private static int eatUntilNextSingleQuote(final String command, final int offset) {
    return eatUntilChar(command, offset, '\"');
  }

  private static int eatUntilNextNewline(final String command, final int offset) {
    return eatUntilChar(command, offset, '\n');
  }

  private static int eatUntilChar(final String command, final int offset, final char ch) {
    for (int i = offset + 1; i < command.length(); i++) {
      if (command.charAt(i) == ch) {
        return i;
      }
    }
    return -1;
  }

  private static String[] trim(final String[] commandTokens) {
    final String[] trimmed = new String[commandTokens.length];
    for (int i = 0; i < commandTokens.length; i++) {
      trimmed[i] = commandTokens[i].trim();
    }
    return trimmed;
  }

  /**
   * Check if one of the tokens if contains the "command" command line option for shells which runs
   * the command given in the next argument.
   */
  private static int getCommandIndex(final String[] commandTokens) {
    for (int i = 0; i < commandTokens.length; i++) {
      if ("-c".equals(commandTokens[i])) {
        return i + 1;
      }
    }
    return -1;
  }

  /** Return true if this looks like a shell path (e.g., /bin/sh, /bin/zsh, etc.) */
  private static boolean isShell(final String commandToken) {
    final File commandFile = new File(commandToken);
    if (new File("/bin").equals(commandFile.getParentFile())) {
      return commandFile.getName().endsWith("sh");
    }
    return SHELL_FILE_NAMES.contains(commandFile.getName());
  }

  private static final List<String> SHELL_FILE_NAMES = List.of("bash", "sh", "zsh", "csh", "tcsh");

  private static final List<String> BANNED_EXECUTABLES =
      List.of(
          // reverse shells, exfiltration, downloading malware
          "nc",
          "curl",
          "wget",
          // installs new system packages
          "dpkg",
          "rpm");

  private static final List<String> SENSITIVE_FILE_NAMES =
      List.of(
          "/etc/passwd",
          "/etc/shadow",
          "/etc/group",
          "/etc/gshadow",
          "/etc/sysconfig/network",
          "/etc/network/interfaces",
          "/etc/resolv.conf",
          "/etc/sudoers",
          "/etc/hosts");
}
