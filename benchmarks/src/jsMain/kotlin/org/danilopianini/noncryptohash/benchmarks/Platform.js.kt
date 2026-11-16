package org.danilopianini.noncryptohash.benchmarks

internal actual val TARGET_NAME: String = "js"

internal actual fun runtimeDescription(): String = "Node.js ${js("process.version")}"

internal actual fun allocatedBytes(): Long? = null

/**
 * Requires Node.js to run with `--expose-gc`, as configured by Gradle.
 */
internal actual fun usedHeapAfterGc(): Long? = if (js("typeof globalThis.gc === 'function'") as Boolean) {
    js("globalThis.gc()")
    (js("process.memoryUsage().heapUsed") as Double).toLong()
} else {
    null
}
