package org.danilopianini.noncryptohash.crc

import org.danilopianini.noncryptohash.HashFunctionTest
import org.danilopianini.noncryptohash.ReferenceVector

/**
 * Reference vectors generated with `java.util.zip.CRC32C`, and checked against Guava
 * and against the check value of the CRC catalogue (the CRC of `123456789`).
 * Hashes are the hexadecimal digits of the 32-bit CRC.
 */
class Crc32cTest : HashFunctionTest<Unit>(32, listOf(Unit), { Crc32c() }) {
    override val byteVectors: List<ReferenceVector<Int, Unit>> = listOf(
        ReferenceVector(0, Unit, "00000000"),
        ReferenceVector(1, Unit, "cbf4f86a"),
        ReferenceVector(2, Unit, "68715542"),
        ReferenceVector(3, Unit, "96818180"),
        ReferenceVector(4, Unit, "ca67959d"),
        ReferenceVector(5, Unit, "b38c4433"),
        ReferenceVector(6, Unit, "756ad48b"),
        ReferenceVector(7, Unit, "d2f5da10"),
        ReferenceVector(8, Unit, "ee89dec3"),
        ReferenceVector(9, Unit, "a1fdb5fa"),
        ReferenceVector(10, Unit, "11ac6bb5"),
        ReferenceVector(11, Unit, "1b388131"),
        ReferenceVector(12, Unit, "d39e6433"),
        ReferenceVector(13, Unit, "665a355f"),
        ReferenceVector(14, Unit, "f35e8859"),
        ReferenceVector(15, Unit, "992c48aa"),
        ReferenceVector(16, Unit, "8d0f4cde"),
        ReferenceVector(17, Unit, "e5f77379"),
        ReferenceVector(18, Unit, "d944109b"),
        ReferenceVector(19, Unit, "ce3fe1d7"),
        ReferenceVector(20, Unit, "fdc5e70c"),
        ReferenceVector(21, Unit, "a2e0cd58"),
        ReferenceVector(22, Unit, "5ee761f0"),
        ReferenceVector(23, Unit, "e91c4938"),
        ReferenceVector(24, Unit, "15f33b92"),
        ReferenceVector(25, Unit, "b05de406"),
        ReferenceVector(26, Unit, "5cfe0434"),
        ReferenceVector(27, Unit, "d9fd19ec"),
        ReferenceVector(28, Unit, "ee82d600"),
        ReferenceVector(29, Unit, "96077203"),
        ReferenceVector(30, Unit, "3c1b21b6"),
        ReferenceVector(31, Unit, "5558cd30"),
        ReferenceVector(32, Unit, "c69c9ebd"),
        ReferenceVector(33, Unit, "6444ef48"),
        ReferenceVector(34, Unit, "4a68b366"),
        ReferenceVector(35, Unit, "d3cf3401"),
        ReferenceVector(36, Unit, "db79f031"),
        ReferenceVector(37, Unit, "fede9586"),
        ReferenceVector(38, Unit, "50885529"),
        ReferenceVector(39, Unit, "f0666ea2"),
        ReferenceVector(40, Unit, "1fcefaef"),
        ReferenceVector(63, Unit, "87b7efe8"),
        ReferenceVector(64, Unit, "3d0f7d5d"),
        ReferenceVector(65, Unit, "64bf7cab"),
        ReferenceVector(127, Unit, "96e0531d"),
        ReferenceVector(255, Unit, "3bde7b18"),
        ReferenceVector(256, Unit, "0d505d78"),
        ReferenceVector(300, Unit, "dc2662b7"),
    )

    override val textVectors: List<ReferenceVector<String, Unit>> = listOf(
        ReferenceVector("", Unit, "00000000"),
        ReferenceVector("a", Unit, "c1d04330"),
        ReferenceVector("abc", Unit, "364b3fb7"),
        ReferenceVector("hello", Unit, "9a71bb4c"),
        ReferenceVector("123456789", Unit, "e3069283"),
        ReferenceVector("The quick brown fox jumps over the lazy dog", Unit, "22620404"),
        ReferenceVector("\u65E5\u672C\u8A9E \uD83D\uDE00", Unit, "c6430f3f"),
    )
}
