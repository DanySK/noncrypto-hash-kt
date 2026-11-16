package org.danilopianini.noncryptohash.benchmarks

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.murmur3.MurmurHash128

/**
 * Every hash function under benchmark. Register new algorithms here.
 */
internal val ALGORITHMS: List<HashFunction> = listOf(
    MurmurHash128(),
)

/**
 * The name of the algorithm in the results.
 */
internal val HashFunction.benchmarkName: String get() = this::class.simpleName ?: toString()
