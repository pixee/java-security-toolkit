import org.javamodularity.moduleplugin.extensions.ModularityExtension

plugins {
    `java-library`
    `maven-publish`
    signing
    jacoco
    id("com.netflix.nebula.contacts") version "7.0.1"
    id("com.netflix.nebula.source-jar") version "20.3.0"
    id("com.netflix.nebula.javadoc-jar") version "20.3.0"
    id("com.netflix.nebula.maven-publish") version "20.3.0"
    id("com.netflix.nebula.publish-verification") version "20.3.0"
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    id("org.javamodularity.moduleplugin") version "1.8.12"
}

tasks.named<Jar>("javadocJar") {
    exclude("module-info.class")
}

tasks.named<Jar>("sourcesJar") {
    dependsOn("compileModuleInfoJava")
    exclude("module-info.class")
}

tasks.named<JavaCompile>("compileJava") {
    options.release.set(null as Int?)
}

configure<ModularityExtension> {
    mixedJavaRelease(8)
}

tasks.named<JavaCompile>("compileModuleInfoJava") {
    options.release.set(null as Int?)
}

repositories {
   mavenCentral()
}

val java11SourceSet = sourceSets.create("java11") {
    java.srcDir("src/java11/main")
    compileClasspath += sourceSets.main.get().output
}

java {
    withSourcesJar()
    withJavadocJar()
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))
    }

    registerFeature("java11") {
        usingSourceSet(java11SourceSet)
    }
}

dependencies {
    api("com.martiansoftware:jsap:2.1")
    api("commons-io:commons-io:2.11.0")
    java11SourceSet.apiConfigurationName("commons-io:commons-io:2.11.0")
    testImplementation("commons-fileupload:commons-fileupload:1.5")
    testImplementation("org.junit.jupiter:junit-jupiter:5.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.hamcrest:hamcrest-all:1.3")
    testImplementation("org.mockito:mockito-core:4.0.0")
}

tasks.named<JavaCompile>(java11SourceSet.compileJavaTaskName) {
    options.release.set(9)
}

tasks.jar {
    into("META-INF/versions/11") {
        from(java11SourceSet.output)
    }
    manifest.attributes(
        Pair("Multi-Release", "true")
    )

    inputs.files(tasks.named(java11SourceSet.compileJavaTaskName).map { it.outputs.files })
}

tasks.named(java11SourceSet.jarTaskName) {
    // disabled because we don't want to publish this separately
    enabled = false
}

group = "io.github.pixee"
version = "1.0.7"
description = "java-security-toolkit"


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

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}

publishing {
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

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        csv.required.set(true)
    }
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
    extensions.configure(org.javamodularity.moduleplugin.extensions.TestModuleOptions::class) {
        // Avoid modules in tests so we can test against Java/JDK 8.
        setRunOnClasspath(true)
    }

    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(8))
    })
}

val java11Test = tasks.register<Test>("testOn11") {
    useJUnitPlatform()
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(11))
    })
}

val java17Test = tasks.register<Test>("testOn17") {
    useJUnitPlatform()
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(17))
    })
}


tasks.check {
    dependsOn(java11Test, java17Test)
}

tasks.compileTestJava {
    extensions.configure(org.javamodularity.moduleplugin.extensions.CompileTestModuleOptions::class) {
        // Avoid modules in tests so we can test against Java/JDK 8.
        setCompileOnClasspath(true)
    }
    options.release.set(8)
}
