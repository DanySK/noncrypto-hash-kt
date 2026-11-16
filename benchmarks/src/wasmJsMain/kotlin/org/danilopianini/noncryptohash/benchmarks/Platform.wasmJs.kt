@file:OptIn(ExperimentalWasmJsInterop::class)

package org.danilopianini.noncryptohash.benchmarks

internal actual val TARGET_NAME: String = "wasmJs"

internal actual fun runtimeDescription(): String = "Node.js ${nodeVersion()} (Wasm GC)"

internal actual fun allocatedBytes(): Long? = null

/**
 * Wasm GC objects live in the JavaScript heap, so the Node.js heap usage includes them.
 * Requires Node.js to run with `--expose-gc`, as configured by Gradle.
 */
internal actual fun usedHeapAfterGc(): Long? = if (hasGc()) {
    collectGarbage()
    heapUsed().toLong()
} else {
    null
}

private fun nodeVersion(): String = js("process.version")

private fun hasGc(): Boolean = js("typeof globalThis.gc === 'function'")

private fun collectGarbage(): Unit = js("globalThis.gc()")

private fun heapUsed(): Double = js("process.memoryUsage().heapUsed")
