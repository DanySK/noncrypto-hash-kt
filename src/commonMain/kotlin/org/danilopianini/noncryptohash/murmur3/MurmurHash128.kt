package org.danilopianini.noncryptohash.murmur3

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.HashFunction

/**
 * MurmurHash3, x64 128-bit variant (`MurmurHash3_x64_128` in the reference implementation by Austin Appleby).
 *
 * The 32-bit [seed] is zero-extended to 64 bits, as in the reference implementation.
 * Guava's `murmur3_128` sign-extends it instead, so the two agree only for non-negative seeds.
 *
 * The 128-bit value is `h2 << 64 | h1`, where `h1` and `h2` are the two 64-bit halves computed by the
 * reference implementation. Hence:
 * - [Digest.digestLong] returns `h1` (as Guava's `HashCode.asLong()`);
 * - [Digest.digest] returns `h2` then `h1`, both big-endian:
 *   the reverse of the bytes written by the reference implementation (and by Guava's `HashCode.asBytes()`),
 *   and the hexadecimal digits of the 128-bit value in their natural order.
 *
 * @property seed the seed of every digest created by [newDigest].
 */
class MurmurHash128(val seed: Int = 0) : HashFunction {
    override val bits: Int = MurmurHash128Digest.BITS

    override fun newDigest(): MurmurHash128Digest = MurmurHash128Digest(seed)
}
