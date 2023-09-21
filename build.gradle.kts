plugins {
    `java-library`
    `maven-publish`
    signing
    id("com.netflix.nebula.contacts") version "7.0.1"
    id("com.netflix.nebula.source-jar") version "20.3.0"
    id("com.netflix.nebula.javadoc-jar") version "20.3.0"
    id("com.netflix.nebula.maven-publish") version "20.3.0"
    id("com.netflix.nebula.publish-verification") version "20.3.0"
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"

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

tasks.compileJava {
    options.release.set(11)
}

extensions.getByType<nebula.plugin.contacts.ContactsExtension>().run {
    addPerson(
        "support@pixee.ai",
        delegateClosureOf<nebula.plugin.contacts.Contact> {
            moniker("Pixee")
            github("pixee")
        },
    )
}

val publicationName = "nebula"
signing {
    if (providers.environmentVariable("CI").isPresent) {
        val signingKey: String? by project
        val signingPassword: String? by project
        useInMemoryPgpKeys(signingKey, signingPassword)
    }
    sign(extensions.getByType<PublishingExtension>().publications.getByName(publicationName))
}

publishing {
    repositories {
        maven {
            name = "pixeeArtifactory"
            url = uri("https://pixee.jfrog.io/artifactory/default-maven-virtual")
            credentials(PasswordCredentials::class)
        }
    }

    publications {
        named<MavenPublication>(publicationName) {
            pom {
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("http://www.opensource.org/licenses/mit-license.php")
                    }
                }
                val scmHost = "github.com"
                val scmProject = "pixee/java-security-toolkit"
                val projectUrl = "https://$scmHost/$scmProject"
                url.set(projectUrl)
                scm {
                    url.set(projectUrl)
                    connection.set("scm:git:git@$scmHost:$scmProject")
                    developerConnection.set(connection)
                }
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
}