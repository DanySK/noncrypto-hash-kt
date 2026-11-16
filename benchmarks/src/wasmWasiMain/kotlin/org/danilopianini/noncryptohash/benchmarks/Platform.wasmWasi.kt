package org.danilopianini.noncryptohash.benchmarks

internal actual val TARGET_NAME: String = "wasmWasi"

internal actual fun runtimeDescription(): String = "WASI on Node.js"

/**
 * WASI exposes no memory statistics.
 */
internal actual fun allocatedBytes(): Long? = null

/**
 * WASI exposes no memory statistics.
 */
internal actual fun usedHeapAfterGc(): Long? = null
