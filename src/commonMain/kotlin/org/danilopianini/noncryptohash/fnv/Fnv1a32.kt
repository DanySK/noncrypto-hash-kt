package org.danilopianini.noncryptohash.fnv

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.requireRange
import org.danilopianini.noncryptohash.fnv.Fnv1a32Digest.Companion.OFFSET_BASIS
import org.danilopianini.noncryptohash.fnv.Fnv1a32Digest.Companion.absorbBytes

/**
 * FNV-1a, 32-bit variant, by Glenn Fowler, Landon Curt Noll, and Kiem-Phong Vo,
 * as in [RFC draft-eastlake-fnv](https://datatracker.ietf.org/doc/draft-eastlake-fnv/).
 *
 * FNV-1a has no seed, needs no buffer, and processes one byte at a time with a single multiplication.
 * It is very fast for keys of a few bytes, and uses 32-bit arithmetic only,
 * but it is slower than block-based hashes (such as [XxHash32][org.danilopianini.noncryptohash.xxhash.XxHash32])
 * on longer inputs, and its distribution is weaker.
 *
 * [Digest.digestLong][org.danilopianini.noncryptohash.Digest.digestLong] zero-extends the hash,
 * and [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns its 4 bytes big-endian.
 *
 * The one-shot byte array methods hash without allocating a digest.
 */
class Fnv1a32 : HashFunction {
    override val bits: Int = Int.SIZE_BITS

    override fun hashInt(bytes: ByteArray, offset: Int, length: Int): Int {
        requireRange(bytes, offset, length)
        return absorbBytes(OFFSET_BASIS, bytes, offset, offset + length)
    }

    override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long =
        hashInt(bytes, offset, length).toLong() and INT_MASK

    override fun newDigest(): Fnv1a32Digest = Fnv1a32Digest()

    private companion object {
        private const val INT_MASK: Long = 0xFFFF_FFFFL
    }
}
