package io.pixee.security;

/**
 * The set of restrictions that we can apply to a secured XML read.
 *
 * @see XMLInputFactorySecurity
 */
public enum XMLRestrictions {
    DISALLOW_DOCTYPE,
    DISALLOW_EXTERNAL_ENTITIES
}
