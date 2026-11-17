package org.danilopianini.noncryptohash.siphash

/**
 * SipHash-2-4: SipHash with 2 SipRound(s) per block and 4 in the finalization,
 * the original variant, recommended by the authors, and used by Guava's `Hashing.sipHash24`.
 *
 * See [SipHashFunction] for the key and the representation of the hash.
 */
class SipHash24(k0: Long, k1: Long) : SipHashFunction(k0, k1) {
    override val compressionRounds: Int = 2
    override val finalizationRounds: Int = 4
}
