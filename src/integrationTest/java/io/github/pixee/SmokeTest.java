package io.github.pixee;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import java.nio.file.Path;


final class SmokeTest {

    @ParameterizedTest
    @ValueSource(strings = {"pixee/hello-world-modules", "pixee/hello-world"})
    void containerStarts(final String imageName) {
        Path securityToolkitJarPath = Path.of(System.getProperty("securityToolkitJarPath"));

        try (
                GenericContainer<?> container = new GenericContainer<>(imageName)
                        .withCopyFileToContainer(MountableFile.forHostPath(securityToolkitJarPath), "/app/libs/")
                        .waitingFor(Wait.forLogMessage("Hello, World!\n", 1))
        ) {
            container.start();
        }
    }
}
