package org.danilopianini.noncryptohash.fnv

import org.danilopianini.noncryptohash.HashFunctionTest
import org.danilopianini.noncryptohash.ReferenceVector

/**
 * Reference vectors computed from the specification, and checked against its published values
 * and against the Rust `fnv` crate (FNV-1a has no seed).
 * Hashes are the hexadecimal digits of the 64-bit value.
 */
class Fnv1a64Test : HashFunctionTest<Unit>(64, listOf(Unit), { Fnv1a64() }) {
    override val byteVectors: List<ReferenceVector<Int, Unit>> = listOf(
        ReferenceVector(0, Unit, "cbf29ce484222325"),
        ReferenceVector(1, Unit, "af63c64c8601c72a"),
        ReferenceVector(2, Unit, "08510e07b505512e"),
        ReferenceVector(3, Unit, "270c521898097401"),
        ReferenceVector(4, Unit, "6363faca5810ed01"),
        ReferenceVector(5, Unit, "f3d0c3d3a4c3c37a"),
        ReferenceVector(6, Unit, "0f807ea0f8a59bda"),
        ReferenceVector(7, Unit, "fcf25e868166b7a9"),
        ReferenceVector(8, Unit, "368e458de18a10c5"),
        ReferenceVector(9, Unit, "3dd126163d9ad202"),
        ReferenceVector(10, Unit, "a53611caae136eee"),
        ReferenceVector(11, Unit, "ce4ece65cb04e3c9"),
        ReferenceVector(12, Unit, "94cc21f7f94e6ed1"),
        ReferenceVector(13, Unit, "254bce5ca0450f62"),
        ReferenceVector(14, Unit, "a4df356455596e4a"),
        ReferenceVector(15, Unit, "80b6147d06f684a1"),
        ReferenceVector(16, Unit, "abe96772d4e34c95"),
        ReferenceVector(17, Unit, "00e7961fbe3b820a"),
        ReferenceVector(18, Unit, "c506a1f03f1ed07e"),
        ReferenceVector(19, Unit, "e916063b415ce421"),
        ReferenceVector(20, Unit, "6d5181b010d8fb51"),
        ReferenceVector(21, Unit, "9a7b1c2ca0b3c3da"),
        ReferenceVector(22, Unit, "32f4add51175b70a"),
        ReferenceVector(23, Unit, "0b7a940cab064ba9"),
        ReferenceVector(24, Unit, "879588869bb314b5"),
        ReferenceVector(25, Unit, "162b32ba914b57c2"),
        ReferenceVector(26, Unit, "f6be9d04e305891e"),
        ReferenceVector(27, Unit, "4b6ea24dc2693189"),
        ReferenceVector(28, Unit, "962f452158bf1401"),
        ReferenceVector(29, Unit, "f1668da9ccaf2162"),
        ReferenceVector(30, Unit, "e0641586cd95b2ba"),
        ReferenceVector(31, Unit, "dfc36f0f555eea21"),
        ReferenceVector(32, Unit, "98005e0e1048b9c5"),
        ReferenceVector(33, Unit, "91593fe5ab9315ea"),
        ReferenceVector(34, Unit, "8dbccd428aed118e"),
        ReferenceVector(35, Unit, "c4e2431210d4b401"),
        ReferenceVector(36, Unit, "612c12b2996e09e1"),
        ReferenceVector(37, Unit, "8beda37ab5fac43a"),
        ReferenceVector(38, Unit, "bf912783391babba"),
        ReferenceVector(39, Unit, "9f5156fa0a03e7a9"),
        ReferenceVector(40, Unit, "bb1dd1df04a190e5"),
    )

    override val textVectors: List<ReferenceVector<String, Unit>> = listOf(
        ReferenceVector("", Unit, "cbf29ce484222325"),
        ReferenceVector("a", Unit, "af63dc4c8601ec8c"),
        ReferenceVector("abc", Unit, "e71fa2190541574b"),
        ReferenceVector("hello", Unit, "a430d84680aabd0b"),
        ReferenceVector("The quick brown fox jumps over the lazy dog", Unit, "f3f9b7f5e7e47110"),
        ReferenceVector("\u65E5\u672C\u8A9E \uD83D\uDE00", Unit, "0ec529321cc08ee8"),
    )
}
