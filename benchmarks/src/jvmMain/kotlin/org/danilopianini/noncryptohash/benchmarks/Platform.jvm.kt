package org.danilopianini.noncryptohash.benchmarks

import com.sun.management.ThreadMXBean as AllocationAwareThreadMXBean
import java.lang.management.ManagementFactory

private const val GC_ATTEMPTS: Int = 3
private const val GC_PAUSE_MILLIS: Long = 50

private val threads: AllocationAwareThreadMXBean? =
    (ManagementFactory.getThreadMXBean() as? AllocationAwareThreadMXBean)
        ?.takeIf { it.isThreadAllocatedMemorySupported }
        ?.apply { isThreadAllocatedMemoryEnabled = true }

internal actual val TARGET_NAME: String = "jvm"

internal actual fun runtimeDescription(): String =
    "${System.getProperty("java.vm.name")} ${System.getProperty("java.runtime.version")}"

internal actual fun allocatedBytes(): Long? = threads?.currentThreadAllocatedBytes

internal actual fun usedHeapAfterGc(): Long? {
    repeat(GC_ATTEMPTS) {
        System.gc()
        Thread.sleep(GC_PAUSE_MILLIS)
    }
    val runtime = Runtime.getRuntime()
    return runtime.totalMemory() - runtime.freeMemory()
}
