package io.github.pixee.security;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.*;
import java.nio.file.Files;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

final class ObjectInputFiltersTest {

  private static DiskFileItem gadget; // this is an evil gadget type
  private static byte[] serializedGadget; // this the serialized bytes of that gadget

  @BeforeAll
  static void setup() throws IOException {
    var baos = new ByteArrayOutputStream();
    gadget =
        new DiskFileItem(
            "fieldName",
            "text/html",
            false,
            "foo.html",
            100,
            Files.createTempDirectory("adi").toFile());
    gadget.getOutputStream(); // needed to make the object serializable
    var oos = new ObjectOutputStream(baos);
    oos.writeObject(gadget);
    serializedGadget = baos.toByteArray();
  }

  @Test
  void default_is_unprotected() throws Exception {
    var ois = new ObjectInputStream(new ByteArrayInputStream(serializedGadget));
    Object o = ois.readObject();
    assertThat(o instanceof DiskFileItem, is(true));
  }

  @Test
  void validating_ois_works() throws Exception {
    var ois =
        ObjectInputFilters.createSafeObjectInputStream(new ByteArrayInputStream(serializedGadget));
    assertThrows(
        InvalidClassException.class,
        () -> {
          ois.readObject();
          fail("this should have been blocked");
        });
  }

  @Test
  void ois_harden_works() throws Exception {
    var ois = new ObjectInputStream(new ByteArrayInputStream(serializedGadget));
    ObjectInputFilters.enableObjectFilterIfUnprotected(ois);
    assertThrows(
        InvalidClassException.class,
        () -> {
          ois.readObject();
          fail("this should have been blocked");
        });
  }

  @Test
  void objectinputfilter_works_when_none_present() throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedGadget));
    ois.setObjectInputFilter(ObjectInputFilters.getHardenedObjectFilter());
    assertThrows(
        InvalidClassException.class,
        () -> {
          ois.readObject();
          fail("this should have been blocked");
        });
  }

  /**
   * This test makes sure that if there's an existing {@link ObjectInputFilter}, that we honor it
   * while we also do our protection. It bans a BadType, and allows a GoodType, so that behavior
   * should still work as well as still reject our evil gadgets.
   */
  @Test
  void objectinputfilter_works_and_honors_existing() throws Exception {
    var filter =
        ObjectInputFilter.Config.createFilter(
            "!" + BadType.class.getName() + ";" + GoodType.class.getName());
    {
      ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedGadget));
      ois.setObjectInputFilter(
          ObjectInputFilters.createCombinedHardenedObjectFilter(filter)); // this is our weave
      assertThrows(
          InvalidClassException.class,
          () -> {
            ois.readObject();
            fail("this should have been blocked");
          });
    }

    // make sure we still reject the bad type
    {
      byte[] serializedBadType = serialize(new BadType());
      var ois = new ObjectInputStream(new ByteArrayInputStream(serializedBadType));
      ois.setObjectInputFilter(
          ObjectInputFilters.createCombinedHardenedObjectFilter(filter)); // this is our weave

      assertThrows(
          InvalidClassException.class,
          () -> {
            ois.readObject();
            fail("this should have been blocked -- the original filter should have rejected it");
          });
    }

    // make we still allow the good type
    {
      byte[] serializedGoodType = serialize(new GoodType());
      var ois = new ObjectInputStream(new ByteArrayInputStream(serializedGoodType));
      ois.setObjectInputFilter(ObjectInputFilters.createCombinedHardenedObjectFilter(filter));
      GoodType goodType = (GoodType) ois.readObject();
      assertThat(goodType, is(notNullValue()));
    }
  }

  byte[] serialize(Serializable s) throws IOException {
    var stream = new ByteArrayOutputStream();
    new ObjectOutputStream(stream).writeObject(s);
    return stream.toByteArray();
  }

  static class BadType implements Serializable {}

  static class GoodType implements Serializable {}
}
