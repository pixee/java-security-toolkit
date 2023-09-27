package io.github.pixee.testapp;

import io.github.pixee.security.HostValidator;

public final class Main {

    public static void main(final String[] args) {
        String message = "Hello, World!";
        if (HostValidator.DENY_COMMON_INFRASTRUCTURE_TARGETS.isAllowed(message)) {
            System.out.println(message);
        } else {
            System.out.println("Access denied");
        }
    }
}
