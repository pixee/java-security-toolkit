package io.github.pixee.security;

import static io.github.pixee.security.J8ApiBridge.setOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;

final class XMLInputFactorySecurityTest {

  @Test
  void xxe_works_in_xmlinputfactory() throws IOException, XMLStreamException {
    String exploit = generateExploit();
    XMLInputFactory factory = XMLInputFactory.newFactory();
    String secretText = getSecretText(factory, exploit);
    assertThat("s3cr3t", equalTo(secretText));
  }

  @Test
  void it_prevents_xxe_in_xmlinputfactory() throws IOException, XMLStreamException {
    String exploit = generateExploit();
    XMLInputFactory factory = XMLInputFactorySecurity.hardenFactory(XMLInputFactory.newFactory());
    String secretText = getSecretText(factory, exploit);
    assertThat("", equalTo(secretText)); // string is empty instead of secret!
  }

  @Test
  void it_fails_when_invalid_restrictions() {
    assertThrows(
        IllegalArgumentException.class,
        () -> XMLInputFactorySecurity.hardenFactory(XMLInputFactory.newFactory(), setOf()));
  }

  @Test
  void it_prevents_xxe_in_xmlinputfactory_doctype_only_restriction() throws IOException {
    String exploit = generateExploit();
    XMLInputFactory factory =
        XMLInputFactorySecurity.hardenFactory(
            XMLInputFactory.newFactory(), setOf(XMLRestrictions.DISALLOW_DOCTYPE));
    assertThrows(XMLStreamException.class, () -> getSecretText(factory, exploit));
  }

  @Test
  void it_prevents_xxe_in_xmlinputfactory_external_entity_only_restriction()
      throws IOException, XMLStreamException {
    String exploit = generateExploit();
    XMLInputFactory factory =
        XMLInputFactorySecurity.hardenFactory(
            XMLInputFactory.newFactory(), setOf(XMLRestrictions.DISALLOW_EXTERNAL_ENTITIES));
    String secretText = getSecretText(factory, exploit);
    assertThat("", equalTo(secretText)); // string is empty instead of secret!
  }

  private String generateExploit() throws IOException {
    String exploit =
        FileUtils.readFileToString(new File("src/test/resources/xxe.xml"), StandardCharsets.UTF_8);
    exploit =
        exploit.replace("$PATH$", new File("src/test/resources/secret.txt").getAbsolutePath());
    return exploit;
  }

  private String getSecretText(final XMLInputFactory factory, final String exploit)
      throws XMLStreamException {
    XMLEventReader xmlEventReader = factory.createXMLEventReader(new StringReader(exploit));
    eatEventsUntil(xmlEventReader, StartElement.class);
    return xmlEventReader.getElementText();
  }

  private <T> void eatEventsUntil(XMLEventReader xmlEventReader, Class<T> type)
      throws XMLStreamException {
    while (xmlEventReader.hasNext()) {
      XMLEvent xmlEvent = xmlEventReader.nextEvent();
      if (type.isAssignableFrom((xmlEvent.getClass()))) {
        return;
      }
    }
    throw new IllegalStateException("never saw that type");
  }
}
