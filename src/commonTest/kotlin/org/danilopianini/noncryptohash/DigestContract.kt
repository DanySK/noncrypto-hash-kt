package org.danilopianini.noncryptohash

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Checks shared by every [Digest] implementation, given a factory of digests in the same initial state.
 */
internal class DigestContract(private val newDigest: () -> Digest) {

    /**
     * Checks that absorbing [input] in chunks of any size gives [expectedHex].
     */
    fun assertChunkingDoesNotMatter(input: ByteArray, expectedHex: String, message: String) {
        listOf(1, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 257, 1000).forEach { chunk ->
            val digest = newDigest()
            input.indices.step(chunk).forEach { start -> digest.update(input, start, minOf(chunk, input.size - start)) }
            assertEquals(expectedHex, digest.digest().toHex(), "$message, chunk $chunk")
        }
    }

    /**
     * Checks every shared property that does not depend on reference vectors.
     */
    fun assertAll() {
        assertDigestingDoesNotAlterState()
        assertDigestIntoHonorsTheOffset()
        assertFixedWidthUpdatesMatchTheirBytes()
        assertResettingRestoresTheInitialState()
    }

    private fun assertDigestingDoesNotAlterState() {
        val digest = newDigest().update(testInput(20))
        val first = digest.digest()
        digest.digestLong()
        digest.digestInt()
        assertContentEquals(first, digest.digest())
        digest.update(testInput(5))
        assertContentEquals(newDigest().update(testInput(20)).update(testInput(5)).digest(), digest.digest())
    }

    private fun assertDigestIntoHonorsTheOffset() {
        val digest = newDigest().update("abc")
        val bytes = digest.bits / Byte.SIZE_BITS
        val destination = ByteArray(bytes + 4)
        digest.digestInto(destination, 3)
        assertContentEquals(digest.digest(), destination.copyOfRange(3, 3 + bytes))
        assertFailsWith<IllegalArgumentException> { digest.digestInto(ByteArray(bytes), 1) }
    }

    private fun assertFixedWidthUpdatesMatchTheirBytes() {
        val values = listOf(0x0123_4567_89AB_CDEFL, -1L, 0x8000_0000_0000_0001UL.toLong())
        (0 until 32).forEach { prefix ->
            values.forEach { value ->
                val expected = newDigest().update(testInput(prefix))
                    .update(value.littleEndian(Long.SIZE_BYTES))
                    .update(value.littleEndian(Int.SIZE_BYTES))
                    .update(value.littleEndian(Short.SIZE_BYTES))
                    .update(value.littleEndian(Byte.SIZE_BYTES))
                val actual = newDigest().update(testInput(prefix))
                    .update(value)
                    .update(value.toInt())
                    .update(value.toShort())
                    .update(value.toByte())
                assertEquals(expected.digest().toHex(), actual.digest().toHex(), "prefix $prefix, value $value")
            }
        }
    }

    private fun assertResettingRestoresTheInitialState() {
        val digest = newDigest().update(testInput(33))
        digest.reset()
        assertContentEquals(newDigest().update("abc").digest(), digest.update("abc").digest())
    }

    private fun Long.littleEndian(bytes: Int): ByteArray = ByteArray(bytes) {
        (this ushr (it * Byte.SIZE_BITS)).toByte()
    }
}

/**
 * The lowercase hexadecimal digits of these bytes.
 */
internal fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

/**
 * The deterministic input used to generate the reference vectors: byte `i` is `i * 37 + 11`.
 */
internal fun testInput(size: Int): ByteArray = ByteArray(size) { (it * 37 + 11).toByte() }
