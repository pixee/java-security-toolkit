package io.pixee.security;

import java.util.List;
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

  /**
   * Harden the {@link DocumentBuilderFactory} against XML-based attacks, and promote directly to
   * the API forefront the decision to allow dangerous XML features.
   *
   * @param factory the factory requiring hardening
   * @param expandEntityReferences a parameter which will be passed to {@link
   *     DocumentBuilderFactory#setExpandEntityReferences(boolean)}
   * @param allowXinclude parameter which will be passed to {@link
   *     DocumentBuilderFactory#setXIncludeAware(boolean)}
   */
  public static DocumentBuilderFactory hardenDocumentBuilderFactory(
      final DocumentBuilderFactory factory,
      final boolean expandEntityReferences,
      final boolean allowXinclude) {
    for (String externalEntityFeature : externalEntityFeatures) {
      try {
        factory.setFeature(externalEntityFeature, false);
      } catch (Exception e) {
        // we could have unexpected behavior from XML providers, so we protect execution
        // also some of the features are specifically geared towards singular XML providers
        // and so we expect them not to be supported
      }
    }

    factory.setExpandEntityReferences(expandEntityReferences);
    factory.setXIncludeAware(allowXinclude);

    return factory;
  }

  private static final List<String> externalEntityFeatures =
      List.of(
          "http://apache.org/xml/features/disallow-doctype-decl",
          "http://apache.org/xml/features/disallow-doctype-decl",
          "http://apache.org/xml/features/nonvalidating/load-external-dtd",
          "http://xml.org/sax/features/external-general-entities",
          "http://xml.org/sax/features/external-parameter-entities");
}
