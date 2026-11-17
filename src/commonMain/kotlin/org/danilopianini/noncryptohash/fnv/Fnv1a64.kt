package org.danilopianini.noncryptohash.fnv

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.requireRange
import org.danilopianini.noncryptohash.fnv.Fnv1a64Digest.Companion.OFFSET_BASIS
import org.danilopianini.noncryptohash.fnv.Fnv1a64Digest.Companion.absorbBytes

/**
 * FNV-1a, 64-bit variant, by Glenn Fowler, Landon Curt Noll, and Kiem-Phong Vo,
 * as in [RFC draft-eastlake-fnv](https://datatracker.ietf.org/doc/draft-eastlake-fnv/).
 *
 * FNV-1a has no seed, needs no buffer, and processes one byte at a time with a single multiplication.
 * It is very fast for keys of a few bytes, but slower than block-based hashes
 * (such as [XxHash64][org.danilopianini.noncryptohash.xxhash.XxHash64]) on longer inputs,
 * and its distribution is weaker.
 * On targets where 64-bit integers are emulated, such as JavaScript, prefer [Fnv1a32].
 *
 * [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns the 8 bytes of the hash big-endian.
 *
 * The one-shot byte array methods hash without allocating a digest.
 */
class Fnv1a64 : HashFunction {
    override val bits: Int = Long.SIZE_BITS

    override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long {
        requireRange(bytes, offset, length)
        return absorbBytes(OFFSET_BASIS, bytes, offset, offset + length)
    }

    override fun newDigest(): Fnv1a64Digest = Fnv1a64Digest()
}
