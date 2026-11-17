package org.danilopianini.noncryptohash.benchmarks

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.crc.Crc32
import org.danilopianini.noncryptohash.crc.Crc32c
import org.danilopianini.noncryptohash.fnv.Fnv1a32
import org.danilopianini.noncryptohash.fnv.Fnv1a64
import org.danilopianini.noncryptohash.murmur2.MurmurHash2
import org.danilopianini.noncryptohash.murmur3.MurmurHash128
import org.danilopianini.noncryptohash.murmur3.MurmurHash32
import org.danilopianini.noncryptohash.siphash.SipHash13
import org.danilopianini.noncryptohash.siphash.SipHash24
import org.danilopianini.noncryptohash.xxhash.XxHash128
import org.danilopianini.noncryptohash.xxhash.XxHash3
import org.danilopianini.noncryptohash.xxhash.XxHash32
import org.danilopianini.noncryptohash.xxhash.XxHash64

/**
 * Every hash function under benchmark. Register new algorithms here.
 */
internal val ALGORITHMS: List<HashFunction> = listOf(
    Crc32(),
    Crc32c(),
    Fnv1a32(),
    Fnv1a64(),
    MurmurHash2(),
    MurmurHash128(),
    MurmurHash32(),
    SipHash13(0, 0),
    SipHash24(0, 0),
    XxHash32(),
    XxHash64(),
    XxHash3(),
    XxHash128(),
)

/**
 * The name of the algorithm in the results.
 */
internal val HashFunction.benchmarkName: String get() = this::class.simpleName ?: toString()
