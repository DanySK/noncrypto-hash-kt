package org.danilopianini.noncryptohash.fnv

import org.danilopianini.noncryptohash.HashFunctionTest
import org.danilopianini.noncryptohash.ReferenceVector

/**
 * Reference vectors computed from the specification, and checked against its published values
 * (FNV-1a has no seed).
 * Hashes are the hexadecimal digits of the 32-bit value.
 */
class Fnv1a32Test : HashFunctionTest<Unit>(32, listOf(Unit), { Fnv1a32() }) {
    override val byteVectors: List<ReferenceVector<Int, Unit>> = listOf(
        ReferenceVector(0, Unit, "811c9dc5"),
        ReferenceVector(1, Unit, "0e0c6b4a"),
        ReferenceVector(2, Unit, "978d310e"),
        ReferenceVector(3, Unit, "ee44b241"),
        ReferenceVector(4, Unit, "512492e1"),
        ReferenceVector(5, Unit, "3a929c5a"),
        ReferenceVector(6, Unit, "d2cc8cba"),
        ReferenceVector(7, Unit, "2b00e6a9"),
        ReferenceVector(8, Unit, "596b18e5"),
        ReferenceVector(9, Unit, "999818e2"),
        ReferenceVector(10, Unit, "846eecce"),
        ReferenceVector(11, Unit, "2d9e9dc9"),
        ReferenceVector(12, Unit, "3bb1cf71"),
        ReferenceVector(13, Unit, "aee9fb82"),
        ReferenceVector(14, Unit, "c856ce2a"),
        ReferenceVector(15, Unit, "9ba6a6e1"),
        ReferenceVector(16, Unit, "de58a475"),
        ReferenceVector(17, Unit, "338a746a"),
        ReferenceVector(18, Unit, "0cf60c5e"),
        ReferenceVector(19, Unit, "62566f21"),
        ReferenceVector(20, Unit, "b9122ef1"),
        ReferenceVector(21, Unit, "759e993a"),
        ReferenceVector(22, Unit, "56ab236a"),
        ReferenceVector(23, Unit, "c2689ba9"),
        ReferenceVector(24, Unit, "01ad85d5"),
        ReferenceVector(25, Unit, "fa28e662"),
        ReferenceVector(26, Unit, "98634ffe"),
        ReferenceVector(27, Unit, "1755ad49"),
        ReferenceVector(28, Unit, "76e07d61"),
        ReferenceVector(29, Unit, "996580c2"),
        ReferenceVector(30, Unit, "78ca0fda"),
        ReferenceVector(31, Unit, "e116c361"),
        ReferenceVector(32, Unit, "3dd664a5"),
        ReferenceVector(33, Unit, "667f820a"),
        ReferenceVector(34, Unit, "34bafd2e"),
        ReferenceVector(35, Unit, "dd5d9fc1"),
        ReferenceVector(36, Unit, "5562a5c1"),
        ReferenceVector(37, Unit, "684b4eda"),
        ReferenceVector(38, Unit, "ec8cf51a"),
        ReferenceVector(39, Unit, "f4e69669"),
        ReferenceVector(40, Unit, "4dff5b45"),
    )

    override val textVectors: List<ReferenceVector<String, Unit>> = listOf(
        ReferenceVector("", Unit, "811c9dc5"),
        ReferenceVector("a", Unit, "e40c292c"),
        ReferenceVector("abc", Unit, "1a47e90b"),
        ReferenceVector("hello", Unit, "4f9f2cab"),
        ReferenceVector("The quick brown fox jumps over the lazy dog", Unit, "048fff90"),
        ReferenceVector("\u65E5\u672C\u8A9E \uD83D\uDE00", Unit, "5b411988"),
    )
}
