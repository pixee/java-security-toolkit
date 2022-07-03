package io.pixee.security;

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

  /** Harden the {@link XMLInputFactory} against XML-based attacks. */
  public static XMLInputFactory hardenFactory(final XMLInputFactory factory) {
    try {
      factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    } catch (Exception e) {
      // we could have unexpected behavior from XML providers, so we protect execution
    }
    return factory;
  }
}
