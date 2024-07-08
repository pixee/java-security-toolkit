package io.github.pixee.security;

import java.util.regex.Pattern;

/**
 * This type exposes helper methods to deal with attacks related to SQL Injections.
 */
public final class SQLSecurity {

  private final static Pattern regex = Pattern.compile("[a-zA-Z0-9_]+(.[a-zA-Z0-9_]+)?");

  /**
   * Checks if a given table name is composed entirelly of alphanumeric characters and "_".
   */
  public static boolean alphanumericValidator(final String tableName) {
    return regex.matcher(tableName).matches();
  }
}
