package org.danilopianini.noncryptohash.siphash

/**
 * SipHash-1-3: SipHash with 1 SipRound(s) per block and 3 in the finalization,
 * the faster variant used by the hash tables of Rust and Python.
 *
 * See [SipHashFunction] for the key and the representation of the hash.
 */
class SipHash13(k0: Long, k1: Long) : SipHashFunction(k0, k1) {
    override val compressionRounds: Int = 1
    override val finalizationRounds: Int = 3
}
