package io.pixee.security;

import java.util.Set;
import javax.xml.stream.XMLInputFactory;

/**
 * This type exposes helper methods that will help defend against XXE attacks in {@link
 * XMLInputFactory}.
 *
 * <p>For more on XXE:
 *
 * <p>https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
 */
public final class XMLInputFactorySecurity {

  private XMLInputFactorySecurity() {}

  /** Harden the {@link XMLInputFactory} against external entity attacks. */
  public static XMLInputFactory hardenFactory(final XMLInputFactory factory) {
    return hardenFactory(factory, Set.of(XMLRestrictions.DISALLOW_EXTERNAL_ENTITIES));
  }

  /** Harden the {@link XMLInputFactory} against XML-based attacks with the given restrictions. */
  public static XMLInputFactory hardenFactory(
      final XMLInputFactory factory, final Set<XMLRestrictions> restrictions) {
    if (restrictions == null || restrictions.isEmpty()) {
      throw new IllegalArgumentException("restrictions must be non-null and non-empty");
    }
    try {
      if (restrictions.contains(XMLRestrictions.DISALLOW_EXTERNAL_ENTITIES)) {
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
      }
      if (restrictions.contains(XMLRestrictions.DISALLOW_DOCTYPE)) {
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
      }
    } catch (Exception e) {
      // we could have unexpected behavior from XML providers, so we protect execution
    }
    return factory;
  }
}
