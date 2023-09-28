package io.github.pixee.security;

import org.apache.commons.fileupload.disk.DiskFileItem;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

final class ValidatingObjectInputStreamsTest {

    private static DiskFileItem gadget; // this is an evil gadget type
    private static byte[] serializedGadget; // this the serialized bytes of that gadget

    @BeforeAll
    static void setup() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        gadget =
                new DiskFileItem(
                        "fieldName",
                        "text/html",
                        false,
                        "foo.html",
                        100,
                        Files.createTempDirectory("adi").toFile());
        gadget.getOutputStream(); // needed to make the object serializable
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(gadget);
        serializedGadget = baos.toByteArray();
    }


    @Test
    void validating_ois_works() throws Exception {
        ObjectInputStream ois =
                ValidatingObjectInputStreams.from(new ByteArrayInputStream(serializedGadget));
        assertThrows(
                InvalidClassException.class,
                () -> {
                    ois.readObject();
                    fail("this should have been blocked");
                });
    }


}