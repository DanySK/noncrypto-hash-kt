package org.danilopianini.noncryptohash.benchmarks

import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource
import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.HashFunction

/**
 * Accumulates every hash, and is printed at the end, so that no computation can be eliminated as dead code.
 */
internal var sink: Long = 0

private const val FOOTPRINT_INSTANCES: Int = 100_000
private const val MAX_BATCH_GROWTH: Long = 10
private const val NANOS_PER_SECOND: Double = 1e9

/**
 * Measures [workload] on [algorithm]: warms up while calibrating the batch size so that a batch lasts about
 * [BenchmarkConfig.ROUND_MILLIS], then times [BenchmarkConfig.ROUNDS] batches.
 */
internal fun measure(algorithm: HashFunction, workload: Workload): RawJson {
    val operation = workload.prepare(algorithm)
    val roundTarget = BenchmarkConfig.ROUND_MILLIS.milliseconds
    var batch = 1L
    val warmup = TimeSource.Monotonic.markNow() + BenchmarkConfig.WARMUP_MILLIS.milliseconds
    while (warmup.hasNotPassedNow()) {
        val elapsed = time(operation, batch)
        if (elapsed < roundTarget) {
            val growth = if (elapsed.isPositive()) (roundTarget / elapsed).toLong() else MAX_BATCH_GROWTH
            batch *= growth.coerceIn(2, MAX_BATCH_GROWTH)
        }
    }
    val nanosPerOperation = DoubleArray(BenchmarkConfig.ROUNDS)
    val allocatedBefore = allocatedBytes()
    for (round in nanosPerOperation.indices) {
        nanosPerOperation[round] = time(operation, batch).inWholeNanoseconds.toDouble() / batch
    }
    val allocatedAfter = allocatedBytes()
    val allocatedPerOperation = if (allocatedBefore != null && allocatedAfter != null) {
        (allocatedAfter - allocatedBefore).toDouble() / (batch * BenchmarkConfig.ROUNDS)
    } else {
        null
    }
    nanosPerOperation.sort()
    val median = nanosPerOperation[nanosPerOperation.size / 2]
    return json(
        "algorithm" to algorithm.benchmarkName,
        "workload" to workload.id,
        "label" to workload.label,
        "inputBytes" to workload.inputBytes,
        "bulk" to workload.bulk,
        "batch" to batch,
        "rounds" to BenchmarkConfig.ROUNDS,
        "nsPerOp" to json(
            "median" to median,
            "min" to nanosPerOperation.first(),
            "max" to nanosPerOperation.last(),
        ),
        "bytesPerSecond" to workload.inputBytes * NANOS_PER_SECOND / median,
        "allocatedBytesPerOp" to allocatedPerOperation,
    )
}

/**
 * Measures the memory retained by a digest of [algorithm], in its initial state.
 * Uses the allocation counter where available (exact), the heap size after a garbage collection otherwise.
 */
internal fun footprint(algorithm: HashFunction): RawJson {
    val instances = arrayOfNulls<Digest>(FOOTPRINT_INSTANCES)
    val allocatedBefore = allocatedBytes()
    val (bytes, method) = if (allocatedBefore != null) {
        instances.fill(algorithm)
        val allocatedAfter = checkNotNull(allocatedBytes())
        (allocatedAfter - allocatedBefore).toDouble() / FOOTPRINT_INSTANCES to "allocation counter"
    } else {
        val heapBefore = usedHeapAfterGc()
        if (heapBefore == null) {
            null to "unavailable"
        } else {
            instances.fill(algorithm)
            val heapAfter = checkNotNull(usedHeapAfterGc())
            (heapAfter - heapBefore).coerceAtLeast(0).toDouble() / FOOTPRINT_INSTANCES to "heap after GC"
        }
    }
    sink += instances.count { it != null }
    return json("algorithm" to algorithm.benchmarkName, "bytesPerDigest" to bytes, "method" to method)
}

private fun Array<Digest?>.fill(algorithm: HashFunction) {
    for (index in indices) {
        this[index] = algorithm.newDigest()
    }
}

private fun time(operation: Operation, batch: Long): Duration {
    val start = TimeSource.Monotonic.markNow()
    var accumulator = 0L
    var iteration = 0L
    while (iteration < batch) {
        accumulator += operation.run(iteration.toInt())
        iteration++
    }
    val elapsed = start.elapsedNow()
    sink += accumulator
    return elapsed
}
