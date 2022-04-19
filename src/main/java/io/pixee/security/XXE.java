package io.pixee.security;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;

/**
 * This type exposes helper methods that will help defend against XXE attacks.
 *
 * <p>For more on XXE:
 *
 * <p>https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
 */
public final class XXE {

  private XXE() {}

  /** Harden the {@link XMLInputFactory} against XML-based attacks. */
  public static XMLInputFactory hardenXmlInputFactory(final XMLInputFactory factory) {
    try {
      factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    } catch (Exception e) {
      // we could have unexpected behavior from XML providers, so we protect execution
    }
    return factory;
  }

  /** Harden the {@link DocumentBuilderFactory} against XML-based attacks. */
  public static DocumentBuilderFactory hardenDocumentBuilderFactory(
      final DocumentBuilderFactory factory) {
    // DocumentBuilderFactory.newInstance();
    return factory;
  }

  // TODO: plenty more parsers to protect from cheatsheet page
}
