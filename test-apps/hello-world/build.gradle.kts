plugins {
    java
    id("com.google.cloud.tools.jib") version "3.4.5"
}

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(8))
    }
}

jib.to.image = "pixee/${project.name}"

dependencies {
  compileOnly(project.rootProject)
}