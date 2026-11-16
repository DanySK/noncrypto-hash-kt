package org.danilopianini.noncryptohash.benchmarks

import org.danilopianini.noncryptohash.HashFunction

/**
 * A single benchmarked operation. Receives the iteration index, which is used to vary the input,
 * so that the computation cannot be hoisted out of the measurement loop.
 * A `fun interface` rather than a function type, to avoid boxing on the JVM.
 */
internal fun interface Operation {
    fun run(iteration: Int): Long
}

/**
 * A kind of input to hash. [prepare] does the setup, which is not measured, and returns the operation.
 */
internal class Workload(
    val id: String,
    val label: String,
    val inputBytes: Int,
    val prepare: (HashFunction) -> Operation,
)

private const val KIB: Int = 1024
private const val MIB: Int = KIB * KIB
private const val STRING_LENGTH: Int = 16
private const val STRING_COUNT: Int = 16
private const val INPUT_MULTIPLIER: Int = 31

private fun bytes(id: String, label: String, size: Int) = Workload(id, label, size) { hash ->
    val input = ByteArray(size) { (it * INPUT_MULTIPLIER).toByte() }
    Operation { iteration ->
        input[0] = iteration.toByte()
        hash.hashLong(input)
    }
}

/**
 * The benchmarked workloads: tiny keys, typical of hash tables, up to bulk data.
 */
internal val WORKLOADS: List<Workload> = listOf(
    Workload("long-reused-digest", "Long, reused digest", Long.SIZE_BYTES) { hash ->
        val digest = hash.newDigest()
        Operation { iteration -> digest.reset().update(iteration.toLong()).digestLong() }
    },
    bytes("bytes-8", "8 B", Long.SIZE_BYTES),
    Workload("string-16", "16-char ASCII string", STRING_LENGTH) { hash ->
        val strings = Array(STRING_COUNT) { index -> "key-$index-".padEnd(STRING_LENGTH, 'x') }
        Operation { iteration -> hash.hashLong(strings[iteration and (STRING_COUNT - 1)]) }
    },
    bytes("bytes-64", "64 B", 64),
    bytes("bytes-1KiB", "1 KiB", KIB),
    bytes("bytes-1MiB", "1 MiB", MIB),
)
