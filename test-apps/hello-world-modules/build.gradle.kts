plugins {
    java
    id("com.google.cloud.tools.jib") version "3.4.0"
}

repositories {
    mavenCentral()
}


java {
    modularity.inferModulePath.set(true)
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))
    }
}

jib.container {
    entrypoint = listOf("java", "--module-path", "@/app/jib-classpath-file", "-m", "io.github.pixee.testapp/io.github.pixee.testapp.Main")
}

jib.to.image = "pixee/${project.name}"


dependencies {
    implementation(project.rootProject)
}