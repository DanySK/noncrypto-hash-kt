package org.danilopianini.noncryptohash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Tests shared by every [HashFunction] with [bits] bits, created by [hashFunction] from a seed (or key) of type [S].
 * The digests are checked with each of the [seeds], and one-shot ranges with the first one.
 *
 * Reference vectors are the hexadecimal digits of the hash value:
 * the long and int forms of the hash are its lowest 64 and 32 bits, zero-extended.
 */
abstract class HashFunctionTest<S>(
    private val bits: Int,
    private val seeds: List<S>,
    private val hashFunction: (seed: S) -> HashFunction,
) {
    /**
     * Reference vectors of [testInput] byte arrays of the given size.
     */
    protected abstract val byteVectors: List<ReferenceVector<Int, S>>

    /**
     * Reference vectors of the UTF-8 encoding of text.
     */
    protected abstract val textVectors: List<ReferenceVector<String, S>>

    @Test
    fun `byte arrays match the reference vectors in one shot and in any chunking`() {
        byteVectors.forEach { (size, seed, hex) ->
            val input = testInput(size)
            val hash = hashFunction(seed)
            val message = "size $size, seed $seed"
            assertEquals(hex.low64(), hash.hashLong(input), message)
            assertEquals(hex.low64().toInt(), hash.hashInt(input), message)
            val digest = hash.newDigest().update(input)
            assertEquals(hex, digest.digest().toHex(), message)
            assertEquals(hex.low64(), digest.digestLong(), message)
            DigestContract(hash::newDigest).assertChunkingDoesNotMatter(input, hex, message)
        }
    }

    @Test
    fun `the digest has the declared number of bits`() {
        val hash = hashFunction(seeds.first())
        assertEquals(bits, hash.bits)
        assertEquals(bits / Byte.SIZE_BITS, hash.newDigest().digest().size)
    }

    @Test
    fun `the digest honors the shared contract`() {
        seeds.forEach { seed -> DigestContract(hashFunction(seed)::newDigest).assertAll() }
    }

    @Test
    fun `one shot hashing honors the offset and length`() {
        val input = testInput(LONG_INPUT)
        val hash = hashFunction(seeds.first())
        RANGES.forEach { (offset, length) ->
            assertEquals(
                hash.hashLong(input.copyOfRange(offset, offset + length)),
                hash.hashLong(input, offset, length),
                "offset $offset, length $length",
            )
        }
        assertFailsWith<IllegalArgumentException> { hash.hashLong(input, LONG_INPUT - 10, 11) }
    }

    @Test
    fun `text matches the reference vectors of its UTF-8 encoding`() {
        textVectors.forEach { (text, seed, hex) ->
            val hash = hashFunction(seed)
            assertEquals(hex.low64(), hash.hashLong(text), "'$text', seed $seed")
            assertEquals(hex, hash.newDigest().update(text).digest().toHex(), "'$text', seed $seed")
        }
    }

    private fun String.low64(): Long = takeLast(16).toULong(16).toLong()

    private companion object {
        // Longer than the blocks and internal buffers of every algorithm
        private const val LONG_INPUT = 300
        private val RANGES = listOf(0 to LONG_INPUT, 3 to 0, 5 to 3, 7 to 16, 1 to 37, 9 to 45, 2 to 260, 11 to 289)
    }
}

/**
 * A reference vector: [hex] is the hexadecimal form of the hash of [input] with the given [seed] (or key).
 */
data class ReferenceVector<T, S>(val input: T, val seed: S, val hex: String)
