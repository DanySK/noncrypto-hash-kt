package org.danilopianini.noncryptohash.benchmarks

/**
 * The name of the target, as used in the results.
 */
internal expect val TARGET_NAME: String

/**
 * The runtime executing the benchmark, with its version.
 */
internal expect fun runtimeDescription(): String

/**
 * Bytes allocated so far by the current thread, or null if the runtime does not expose them.
 */
internal expect fun allocatedBytes(): Long?

/**
 * Bytes used by live objects after forcing a garbage collection, or null if the runtime does not expose them.
 */
internal expect fun usedHeapAfterGc(): Long?
