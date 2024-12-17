package io.github.pixee.security;

import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Holds utilities for executing methods and functions within a timeout.
 */
public class ExecuteWithTimeout{


	/**
	 * Tries to execute a given {@link Callable} within a given timeout in milliseconds. Returns the result if successful, otherwise throws a {@link RuntimeException}.
	 */
	public <E> E executeWithTimeout(final Callable<E> action, final int timeout) {
        Future<E> maybeResult = Executors.newSingleThreadExecutor().submit(action);
        try {
            return maybeResult.get(timeout, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute within time limit.");
        }
    }
}
