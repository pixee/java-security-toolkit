package io.github.pixee.security;

import org.apache.commons.io.serialization.ValidatingObjectInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

/**
 * This type exposes helper methods that will help defend against Java deserialization attacks
 * leveraging {@link ObjectInputStream} APIs.
 *
 * <p>For more information on deserialization checkout the <a
 * href="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html">OWASP
 * Cheat Sheet</a>.
 */
public final class SafeObjectInputStream {

    /**
     * Private no-op constructor to prevent accidental initialization of this class
     */
    private SafeObjectInputStream() {}

    /**
     * This method returns a wrapped {@link ObjectInputStream} that protects against deserialization
     * code execution attacks. This method can be used in Java 8 and previous.
     *
     * @param ois the stream to wrap and harden
     * @return an {@link ObjectInputStream} which is safe against all publicly known gadgets
     * @throws IOException if the underlying creation of {@link ObjectInputStream} fails
     */
    public static ObjectInputStream createSafeObjectInputStream(final InputStream ois)
            throws IOException {
        try {
            final ValidatingObjectInputStream is = new ValidatingObjectInputStream(ois);
            for (String gadget : UnwantedTypes.dangerousClassNameTokens()) {
                is.reject("*" + gadget + "*");
            }
            return is;
        } catch (IOException e) {
            // ignored
        }

        // if for some reason we can't replace it, we'll pass it back as it was given
        return new ObjectInputStream(ois);
    }
}
