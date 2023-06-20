package io.github.pixee.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

final class DocumentBuilderFactorySecurityTest {

  @Test
  void xxe_works_in_dbf() throws Exception {
    String exploit = generateExploit();
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    String secretText = getSecretText(factory, exploit);
    assertThat("s3cr3t", equalTo(secretText)); // string is empty instead of secret!
  }

  @Test
  void it_prevents_xxe_in_dbf() throws Exception {
    String exploit = generateExploit();
    DocumentBuilderFactory factory =
        DocumentBuilderFactorySecurity.hardenDocumentBuilderFactory(
            DocumentBuilderFactory.newInstance(), false, false);
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

  private String getSecretText(final DocumentBuilderFactory factory, final String exploit)
      throws Exception {
    ByteArrayInputStream exploitStream =
        new ByteArrayInputStream(exploit.getBytes(StandardCharsets.UTF_8));
    Document doc = factory.newDocumentBuilder().parse(exploitStream);
    return doc.getDocumentElement().getTextContent();
  }
}
