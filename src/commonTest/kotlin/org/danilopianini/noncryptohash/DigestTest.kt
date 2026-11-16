package org.danilopianini.noncryptohash

import kotlin.test.Test
import kotlin.test.assertEquals

class DigestTest {

    @Test
    fun `a text range is absorbed like the corresponding substring`() {
        assertEquals(raw { update("bc") }, raw { update("abcd", 1, 3) })
    }

    @Test
    fun `all NaNs hash the same`() {
        assertEquals(raw { update(Double.NaN) }, raw { update(Double.fromBits(0x7FF8_0000_0000_0001L)) })
        assertEquals(raw { update(Float.NaN) }, raw { update(Float.fromBits(0x7FC0_0001)) })
    }

    @Test
    fun `integers are absorbed little-endian`() {
        assertEquals(bytes(0x02, 0x01), raw { update(0x0102.toShort()) })
        assertEquals(bytes(0x04, 0x03, 0x02, 0x01), raw { update(0x01020304) })
        assertEquals(bytes(8, 7, 6, 5, 4, 3, 2, 1), raw { update(0x0102030405060708L) })
        assertEquals(raw { update(-1) }, raw { update(UInt.MAX_VALUE) })
    }

    @Test
    fun `the byte digest is the big-endian form of the long digest`() {
        val digest = RecordingDigest().update("hello")
        val expected = digest.digestLong()
        val actual = digest.digest().fold(0L) { acc, byte -> (acc shl Byte.SIZE_BITS) or (byte.toLong() and 0xFF) }
        assertEquals(expected, actual)
    }

    @Test
    fun `unpaired surrogates become the replacement character`() {
        val replacement = bytes(0xEF, 0xBF, 0xBD)
        assertEquals(bytes('a'.code) + replacement, raw { update("a\uD83D") })
        assertEquals(replacement + bytes('a'.code), raw { update("\uDE00a") })
    }

    @Test
    fun `well-formed text is absorbed as its UTF-8 encoding`() {
        listOf("", "abc", "àèìòù", "€uro", "日本語", "emoji 😀 ok").forEach { text ->
            assertEquals(text.encodeToByteArray().toList(), raw { update(text) }, text)
        }
    }

    private fun bytes(vararg values: Int) = values.map { it.toByte() }
}
