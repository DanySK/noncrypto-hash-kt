package org.danilopianini.noncryptohash.xxhash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.danilopianini.noncryptohash.DigestContract
import org.danilopianini.noncryptohash.testInput
import org.danilopianini.noncryptohash.toHex

/**
 * Reference vectors generated with the reference C implementation (`XXH32` of libxxhash 0.8).
 * Hashes are the hexadecimal digits of the 32-bit value; seeds are read as unsigned.
 */
class XxHash32Test {
    private val byteVectors: List<Vector<Int>> = listOf(
        Vector(0, 0, "02cc5d05"),
        Vector(1, 0, "3fe5a29d"),
        Vector(2, 0, "78b7fb0e"),
        Vector(3, 0, "4021af28"),
        Vector(4, 0, "1eb8f11a"),
        Vector(5, 0, "07b9db7d"),
        Vector(6, 0, "5dd493ea"),
        Vector(7, 0, "02226fe7"),
        Vector(8, 0, "9d02a89c"),
        Vector(9, 0, "c43ca64f"),
        Vector(10, 0, "786ed32f"),
        Vector(11, 0, "e54a009b"),
        Vector(12, 0, "d40fa400"),
        Vector(13, 0, "78c83171"),
        Vector(14, 0, "e97074da"),
        Vector(15, 0, "162986eb"),
        Vector(16, 0, "96ac9fa6"),
        Vector(17, 0, "3cdfb1a2"),
        Vector(18, 0, "4c41719d"),
        Vector(19, 0, "bed5a0ea"),
        Vector(20, 0, "428f0501"),
        Vector(21, 0, "ad6b01c9"),
        Vector(22, 0, "7c763b03"),
        Vector(23, 0, "12a0921b"),
        Vector(24, 0, "bbc1b5c2"),
        Vector(25, 0, "d76b2de0"),
        Vector(26, 0, "a362fa20"),
        Vector(27, 0, "360e7d31"),
        Vector(28, 0, "46f665e2"),
        Vector(29, 0, "9697f109"),
        Vector(30, 0, "7a7a8211"),
        Vector(31, 0, "df853fbf"),
        Vector(32, 0, "da8072dc"),
        Vector(33, 0, "3c8fd07d"),
        Vector(34, 0, "00eca874"),
        Vector(35, 0, "c52e5aee"),
        Vector(36, 0, "92eff593"),
        Vector(37, 0, "4bd3e28c"),
        Vector(38, 0, "52eedaaf"),
        Vector(39, 0, "349f040e"),
        Vector(40, 0, "3ecc6a67"),
        Vector(0, 42, "d5be6eb8"),
        Vector(1, 42, "dddbd714"),
        Vector(2, 42, "f8928c5f"),
        Vector(3, 42, "fdae9bd7"),
        Vector(4, 42, "640e95d4"),
        Vector(5, 42, "5cc886bb"),
        Vector(6, 42, "82048aec"),
        Vector(7, 42, "0eccc48f"),
        Vector(8, 42, "23c2a410"),
        Vector(9, 42, "7658b3ac"),
        Vector(10, 42, "1de2139c"),
        Vector(11, 42, "360d32da"),
        Vector(12, 42, "277281c0"),
        Vector(13, 42, "85291227"),
        Vector(14, 42, "4109624d"),
        Vector(15, 42, "cdf3e657"),
        Vector(16, 42, "0fdb43fa"),
        Vector(17, 42, "6ff901e6"),
        Vector(18, 42, "0240874e"),
        Vector(19, 42, "0e739beb"),
        Vector(20, 42, "eb8b7102"),
        Vector(21, 42, "2d54ab2c"),
        Vector(22, 42, "8ee0ff27"),
        Vector(23, 42, "21949202"),
        Vector(24, 42, "a62da30e"),
        Vector(25, 42, "7f456ee9"),
        Vector(26, 42, "0317b3d2"),
        Vector(27, 42, "4e53c858"),
        Vector(28, 42, "668a843f"),
        Vector(29, 42, "b70236a0"),
        Vector(30, 42, "3beb09b8"),
        Vector(31, 42, "871292d7"),
        Vector(32, 42, "6b9979a0"),
        Vector(33, 42, "1b6f0444"),
        Vector(34, 42, "73595849"),
        Vector(35, 42, "948fdaa3"),
        Vector(36, 42, "d396c552"),
        Vector(37, 42, "c979047f"),
        Vector(38, 42, "ad358aa1"),
        Vector(39, 42, "a79936e4"),
        Vector(40, 42, "cf703cdf"),
        Vector(0, -1640531535, "36b78ae7"),
        Vector(1, -1640531535, "35bacfe6"),
        Vector(2, -1640531535, "fac836d1"),
        Vector(3, -1640531535, "d3c72124"),
        Vector(4, -1640531535, "dbf0c597"),
        Vector(5, -1640531535, "f4b9fab6"),
        Vector(6, -1640531535, "4e22b2ce"),
        Vector(7, -1640531535, "2e18e53a"),
        Vector(8, -1640531535, "3907e29c"),
        Vector(9, -1640531535, "49d682ed"),
        Vector(10, -1640531535, "49489de3"),
        Vector(11, -1640531535, "8d650f23"),
        Vector(12, -1640531535, "44857320"),
        Vector(13, -1640531535, "a9172d57"),
        Vector(14, -1640531535, "f95c4dff"),
        Vector(15, -1640531535, "5d300d8f"),
        Vector(16, -1640531535, "6d8a765e"),
        Vector(17, -1640531535, "642cf14d"),
        Vector(18, -1640531535, "c6339497"),
        Vector(19, -1640531535, "ce2ea96a"),
        Vector(20, -1640531535, "1d809fc2"),
        Vector(21, -1640531535, "be5366ce"),
        Vector(22, -1640531535, "d2374af7"),
        Vector(23, -1640531535, "b1f972d7"),
        Vector(24, -1640531535, "6bca995a"),
        Vector(25, -1640531535, "17e724b4"),
        Vector(26, -1640531535, "561d9899"),
        Vector(27, -1640531535, "7a88ca87"),
        Vector(28, -1640531535, "e0402a2a"),
        Vector(29, -1640531535, "49bf4275"),
        Vector(30, -1640531535, "64e17d66"),
        Vector(31, -1640531535, "996079fe"),
        Vector(32, -1640531535, "e60dccbd"),
        Vector(33, -1640531535, "8f4a7d52"),
        Vector(34, -1640531535, "282379bb"),
        Vector(35, -1640531535, "a84987dc"),
        Vector(36, -1640531535, "13861a9e"),
        Vector(37, -1640531535, "b2533fd2"),
        Vector(38, -1640531535, "b1bdf70c"),
        Vector(39, -1640531535, "a7acc84e"),
        Vector(40, -1640531535, "3accd05e"),
    )

    private val textVectors: List<Vector<String>> = listOf(
        Vector("", 0, "02cc5d05"),
        Vector("a", 0, "550d7456"),
        Vector("abc", 0, "32d153ff"),
        Vector("hello", 0, "fb0077f9"),
        Vector("The quick brown fox jumps over the lazy dog", 0, "e85ea4de"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 0, "4971f43a"),
        Vector("", 1, "0b2cb792"),
        Vector("a", 1, "f514706f"),
        Vector("abc", 1, "aa3da8ff"),
        Vector("hello", 1, "fcfffba9"),
        Vector("The quick brown fox jumps over the lazy dog", 1, "234f8471"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 1, "10d6d60d"),
        Vector("", 42, "d5be6eb8"),
        Vector("a", 42, "4bedc2db"),
        Vector("abc", 42, "0147abfe"),
        Vector("hello", 42, "4d02c966"),
        Vector("The quick brown fox jumps over the lazy dog", 42, "4c29bb74"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 42, "bef26c1a"),
        Vector("", -1, "9061da9d"),
        Vector("a", -1, "cd42752d"),
        Vector("abc", -1, "b22b1420"),
        Vector("hello", -1, "2711808b"),
        Vector("The quick brown fox jumps over the lazy dog", -1, "5a2a0096"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", -1, "4e0f2cca"),
        Vector("", 2147483647, "c89b854f"),
        Vector("a", 2147483647, "bbb13ba2"),
        Vector("abc", 2147483647, "c4fdac34"),
        Vector("hello", 2147483647, "476e0810"),
        Vector("The quick brown fox jumps over the lazy dog", 2147483647, "083359bc"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 2147483647, "0203b904"),
    )

    @Test
    fun `byte arrays match the reference vectors in one shot`() {
        byteVectors.forEach { (size, seed, hex) ->
            val input = testInput(size)
            assertEquals(hex.toLong(16).toInt(), XxHash32(seed).hashInt(input), "size $size, seed $seed")
            assertEquals(hex.toLong(16), XxHash32(seed).hashLong(input), "size $size, seed $seed")
            assertEquals(hex, XxHash32(seed).newDigest().update(input).digest().toHex(), "size $size, seed $seed")
        }
    }

    @Test
    fun `byte arrays match the reference vectors in any chunking`() {
        byteVectors.forEach { (size, seed, hex) ->
            DigestContract {
                XxHash32Digest(seed)
            }.assertChunkingDoesNotMatter(testInput(size), hex, "size $size, seed $seed")
        }
    }

    @Test
    fun `the digest honors the shared contract`() {
        listOf(0, 7, -1).forEach { seed -> DigestContract { XxHash32Digest(seed) }.assertAll() }
    }

    @Test
    fun `one shot hashing honors the offset and length`() {
        val input = testInput(40)
        listOf(0 to 40, 3 to 0, 5 to 3, 7 to 16, 1 to 37).forEach { (offset, length) ->
            assertEquals(
                XxHash32(42).hashInt(input.copyOfRange(offset, offset + length)),
                XxHash32(42).hashInt(input, offset, length),
                "offset $offset, length $length",
            )
        }
        assertFailsWith<IllegalArgumentException> { XxHash32().hashInt(input, 30, 11) }
    }

    @Test
    fun `text matches the reference vectors of its UTF-8 encoding`() {
        textVectors.forEach { (text, seed, hex) ->
            assertEquals(hex.toLong(16), XxHash32(seed).hashLong(text), "'$text', seed $seed")
            assertEquals(hex, XxHash32(seed).newDigest().update(text).digest().toHex(), "'$text', seed $seed")
        }
    }

    @Test
    fun `the digest has 32 bits and is zero-extended to a long`() {
        assertEquals(32, XxHash32().bits)
        assertEquals(4, XxHash32Digest().digest().size)
        assertEquals(0xd5be_6eb8L, XxHash32(42).hashLong(ByteArray(0)))
        assertEquals(0xd5be_6eb8L, XxHash32Digest(42).digestLong())
    }

    private data class Vector<T>(val input: T, val seed: Int, val hex: String)
}
