rootProject.name = "java-security-toolkit"

plugins {
    id("com.gradle.enterprise") version "3.14.1"
}

val isCI = providers.environmentVariable("CI").isPresent

include("test-apps:hello-world")
gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
        isUploadInBackground = !isCI

        if (isCI) {
            publishAlways()
        }

        capture {
            isTaskInputFiles = true
        }
    }
}
