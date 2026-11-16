package org.danilopianini.noncryptohash.benchmarks

import kotlin.random.Random
import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.FunnelRegistry
import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.updateValue

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
 * [inputBytes] is the number of bytes absorbed per operation.
 * [bulk] workloads are reported as throughput, the others as time per operation.
 */
internal class Workload(
    val id: String,
    val label: String,
    val inputBytes: Int,
    val bulk: Boolean = inputBytes >= KIB,
    val prepare: (HashFunction) -> Operation,
)

private const val KIB: Int = 1024
private const val MIB: Int = KIB * KIB
private const val STRING_LENGTH: Int = 16
private const val STRING_COUNT: Int = 16
private const val INPUT_MULTIPLIER: Int = 31
private const val STRUCTURED_VARIANTS: Int = 8
private const val STRUCTURED_SEED: Int = 42
private const val STRUCTURED_STRINGS: Int = 500
private const val STRUCTURED_INTS: Int = 300
private const val STRUCTURED_LONGS: Int = 100
private const val STRUCTURED_BOOLEANS: Int = 50
private const val STRUCTURED_DOUBLES: Int = 50
private const val MIN_TOKEN_LENGTH: Int = 10
private const val MAX_TOKEN_LENGTH: Int = 100
private const val MAX_INDEX: Int = 1000
private const val TOKEN_ALPHABET: String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._"

/**
 * Lists of 1000 objects shaped like the paths of aggregate programs (e.g., in Collektive):
 * 500 identifier-like strings of 10 to 100 characters, and 500 primitives (mostly small indices), shuffled.
 * Generated with a fixed seed, hence identical on every target.
 */
private val structuredInputs: List<List<Any>> = Random(STRUCTURED_SEED).let { random ->
    List(STRUCTURED_VARIANTS) { pathLike(random) }
}

private fun bytes(id: String, label: String, size: Int) = Workload(id, label, size) { hash ->
    val input = ByteArray(size) { (it * INPUT_MULTIPLIER).toByte() }
    Operation { iteration ->
        input[0] = iteration.toByte()
        hash.hashLong(input)
    }
}

/**
 * The benchmarked workloads: tiny keys, typical of hash tables, up to bulk data, and structured values.
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
    Workload(
        id = "structured-1000",
        label = "1000 objects, structured",
        inputBytes = structuredInputs.sumOf { encodedSize(it) } / STRUCTURED_VARIANTS,
        bulk = false,
    ) { hash ->
        Operation { iteration -> hash.hashValueLong(structuredInputs[iteration and (STRUCTURED_VARIANTS - 1)]) }
    },
)

/**
 * The number of bytes absorbed by the structured encoding of [value].
 */
private fun encodedSize(value: Any): Int = CountingDigest().also { it.updateValue(value, FunnelRegistry.EMPTY) }.count

private fun pathLike(random: Random): List<Any> {
    val tokens = ArrayList<Any>()
    repeat(STRUCTURED_STRINGS) {
        val length = random.nextInt(MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH + 1)
        tokens += CharArray(length) { TOKEN_ALPHABET[random.nextInt(TOKEN_ALPHABET.length)] }.concatToString()
    }
    repeat(STRUCTURED_INTS) { tokens += random.nextInt(MAX_INDEX) }
    repeat(STRUCTURED_LONGS) { tokens += random.nextLong() }
    repeat(STRUCTURED_BOOLEANS) { tokens += random.nextBoolean() }
    repeat(STRUCTURED_DOUBLES) { tokens += random.nextDouble() }
    tokens.shuffle(random)
    return tokens
}

/**
 * A [Digest] that only counts the absorbed bytes.
 */
private class CountingDigest : Digest {
    var count: Int = 0
        private set

    override val bits: Int = Long.SIZE_BITS

    override fun digestInto(destination: ByteArray, offset: Int) = Unit

    override fun digestLong(): Long = count.toLong()

    override fun reset(): Digest = apply { count = 0 }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply { count += length }

    override fun update(value: Byte): Digest = apply { count++ }
}
