@file:OptIn(ExperimentalNativeApi::class, ExperimentalStdlibApi::class, NativeRuntimeApi::class)

package org.danilopianini.noncryptohash.benchmarks

import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.runtime.GC
import kotlin.native.runtime.NativeRuntimeApi

internal actual val TARGET_NAME: String = "native"

internal actual fun runtimeDescription(): String =
    "Kotlin/Native ${KotlinVersion.CURRENT} (${Platform.osFamily}, ${Platform.cpuArchitecture})"

/**
 * Kotlin/Native exposes no allocation counter.
 */
internal actual fun allocatedBytes(): Long? = null

/**
 * Collects twice, as the first collection may still be releasing the garbage of earlier ones.
 * The statistics are coarse (allocator chunks), so callers should allocate many objects.
 */
internal actual fun usedHeapAfterGc(): Long? {
    GC.collect()
    GC.collect()
    return GC.lastGCInfo?.memoryUsageAfter?.values?.sumOf { it.totalObjectsSizeBytes }
}
