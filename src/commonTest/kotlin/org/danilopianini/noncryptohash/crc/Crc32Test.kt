package org.danilopianini.noncryptohash.crc

import org.danilopianini.noncryptohash.HashFunctionTest
import org.danilopianini.noncryptohash.ReferenceVector

/**
 * Reference vectors generated with `java.util.zip.CRC32`, and checked against Guava
 * and against the check value of the CRC catalogue (the CRC of `123456789`).
 * Hashes are the hexadecimal digits of the 32-bit CRC.
 */
class Crc32Test : HashFunctionTest<Unit>(32, listOf(Unit), { Crc32() }) {
    override val byteVectors: List<ReferenceVector<Int, Unit>> = listOf(
        ReferenceVector(0, Unit, "00000000"),
        ReferenceVector(1, Unit, "45d03605"),
        ReferenceVector(2, Unit, "84f4fb98"),
        ReferenceVector(3, Unit, "3753a57b"),
        ReferenceVector(4, Unit, "a5328cbe"),
        ReferenceVector(5, Unit, "9ececd5f"),
        ReferenceVector(6, Unit, "b5416b8c"),
        ReferenceVector(7, Unit, "ef6f3b31"),
        ReferenceVector(8, Unit, "648bad8b"),
        ReferenceVector(9, Unit, "17dc5f9e"),
        ReferenceVector(10, Unit, "a0125457"),
        ReferenceVector(11, Unit, "0919340f"),
        ReferenceVector(12, Unit, "7a6c29ec"),
        ReferenceVector(13, Unit, "7ec47ae4"),
        ReferenceVector(14, Unit, "dca7a3c5"),
        ReferenceVector(15, Unit, "53605ee3"),
        ReferenceVector(16, Unit, "24e8a988"),
        ReferenceVector(17, Unit, "cdfc844a"),
        ReferenceVector(18, Unit, "a97e38a7"),
        ReferenceVector(19, Unit, "3ca5f099"),
        ReferenceVector(20, Unit, "205c4a33"),
        ReferenceVector(21, Unit, "5d472d38"),
        ReferenceVector(22, Unit, "e087c443"),
        ReferenceVector(23, Unit, "6232f06b"),
        ReferenceVector(24, Unit, "84d3195e"),
        ReferenceVector(25, Unit, "2ae492fd"),
        ReferenceVector(26, Unit, "c929ae64"),
        ReferenceVector(27, Unit, "7dc1dd6f"),
        ReferenceVector(28, Unit, "5cc1c1a9"),
        ReferenceVector(29, Unit, "fe87b0c7"),
        ReferenceVector(30, Unit, "f89343a9"),
        ReferenceVector(31, Unit, "4745364c"),
        ReferenceVector(32, Unit, "a9f48115"),
        ReferenceVector(33, Unit, "fe728587"),
        ReferenceVector(34, Unit, "27f3595f"),
        ReferenceVector(35, Unit, "e4265622"),
        ReferenceVector(36, Unit, "fae47145"),
        ReferenceVector(37, Unit, "622893de"),
        ReferenceVector(38, Unit, "f9d49d8c"),
        ReferenceVector(39, Unit, "a291cf9f"),
        ReferenceVector(40, Unit, "837e7e78"),
        ReferenceVector(63, Unit, "bae609d9"),
        ReferenceVector(64, Unit, "ffbae609"),
        ReferenceVector(65, Unit, "4a2f75d7"),
        ReferenceVector(127, Unit, "226e9192"),
        ReferenceVector(255, Unit, "6626d95d"),
        ReferenceVector(256, Unit, "8ed7a350"),
        ReferenceVector(300, Unit, "32ec5e76"),
    )

    override val textVectors: List<ReferenceVector<String, Unit>> = listOf(
        ReferenceVector("", Unit, "00000000"),
        ReferenceVector("a", Unit, "e8b7be43"),
        ReferenceVector("abc", Unit, "352441c2"),
        ReferenceVector("hello", Unit, "3610a686"),
        ReferenceVector("123456789", Unit, "cbf43926"),
        ReferenceVector("The quick brown fox jumps over the lazy dog", Unit, "414fa339"),
        ReferenceVector("\u65E5\u672C\u8A9E \uD83D\uDE00", Unit, "c851e4c7"),
    )
}
