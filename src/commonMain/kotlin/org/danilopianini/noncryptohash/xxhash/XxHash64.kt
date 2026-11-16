package org.danilopianini.noncryptohash.xxhash

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.requireRange
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.BYTE_MASK
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.P1
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.P2
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.P5
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.STRIPE
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.avalanche
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.converge
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.readInt
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.readLong
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.round
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.tailByte
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.tailHalfLane
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.tailLane

/**
 * XXH64, the 64-bit variant of xxHash by Yann Collet, as in its
 * [specification](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md).
 *
 * The [seed] is read as an unsigned 64-bit integer.
 * [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns the 8 bytes of the hash big-endian,
 * as the canonical representation of the specification.
 *
 * The one-shot byte array methods hash without allocating a digest.
 *
 * @property seed the seed of every digest created by [newDigest].
 */
class XxHash64(val seed: Long = 0) : HashFunction {
    override val bits: Int = XxHash64Digest.BITS

    override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long {
        requireRange(bytes, offset, length)
        var index = offset
        val end = offset + length
        var hash = if (length >= STRIPE) {
            var acc1 = seed + P1 + P2
            var acc2 = seed + P2
            var acc3 = seed
            var acc4 = seed - P1
            while (end - index >= STRIPE) {
                acc1 = round(acc1, readLong(bytes, index))
                acc2 = round(acc2, readLong(bytes, index + Long.SIZE_BYTES))
                acc3 = round(acc3, readLong(bytes, index + 2 * Long.SIZE_BYTES))
                acc4 = round(acc4, readLong(bytes, index + 3 * Long.SIZE_BYTES))
                index += STRIPE
            }
            converge(acc1, acc2, acc3, acc4)
        } else {
            seed + P5
        }
        hash += length
        while (end - index >= Long.SIZE_BYTES) {
            hash = tailLane(hash, readLong(bytes, index))
            index += Long.SIZE_BYTES
        }
        if (end - index >= Int.SIZE_BYTES) {
            hash = tailHalfLane(hash, readInt(bytes, index))
            index += Int.SIZE_BYTES
        }
        while (index < end) {
            hash = tailByte(hash, bytes[index++].toLong() and BYTE_MASK)
        }
        return avalanche(hash)
    }

    override fun newDigest(): XxHash64Digest = XxHash64Digest(seed)
}
