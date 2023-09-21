plugins {
    `java-library`
    `maven-publish`
}

repositories {
   mavenCentral()
}

dependencies {
    api("com.coverity.security:coverity-escapers:1.1.1")
    api("com.martiansoftware:jsap:2.1")
    api("commons-io:commons-io:2.11.0")
    api("org.codehaus.mojo:animal-sniffer-annotations:1.23")
    testImplementation("commons-fileupload:commons-fileupload:1.5")
    testImplementation("org.junit.jupiter:junit-jupiter:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.hamcrest:hamcrest-all:1.3")
    testImplementation("org.mockito:mockito-core:4.0.0")
}

group = "io.github.pixee"
version = "1.0.7"
description = "java-security-toolkit"

java {
    withSourcesJar()
    withJavadocJar()
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))
    }
}

publishing {
    publications.create<MavenPublication>("maven") {
        from(components["java"])
    }
}

tasks.test {
    useJUnitPlatform()
}