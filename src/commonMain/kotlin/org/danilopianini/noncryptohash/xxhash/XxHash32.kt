package org.danilopianini.noncryptohash.xxhash

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.requireRange
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.P1
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.P2
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.P5
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.STRIPE
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.avalanche
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.converge
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.readLittleEndian
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.round
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.tailByte
import org.danilopianini.noncryptohash.xxhash.XxHash32Digest.Companion.tailWord

/**
 * XXH32, the 32-bit variant of xxHash by Yann Collet, as in its
 * [specification](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md).
 *
 * It uses 32-bit arithmetic only, which makes it the fastest hash of this library on targets
 * where 64-bit integers are emulated, such as JavaScript.
 *
 * The [seed] is read as an unsigned 32-bit integer.
 * [Digest.digestLong][org.danilopianini.noncryptohash.Digest.digestLong] zero-extends the hash,
 * and [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns its 4 bytes big-endian,
 * as the canonical representation of the specification.
 *
 * The one-shot byte array methods hash without allocating a digest.
 *
 * @property seed the seed of every digest created by [newDigest].
 */
class XxHash32(val seed: Int = 0) : HashFunction {
    override val bits: Int = XxHash32Digest.BITS

    override fun hashInt(bytes: ByteArray, offset: Int, length: Int): Int {
        requireRange(bytes, offset, length)
        var index = offset
        val end = offset + length
        var hash = if (length >= STRIPE) {
            var v1 = seed + P1 + P2
            var v2 = seed + P2
            var v3 = seed
            var v4 = seed - P1
            while (end - index >= STRIPE) {
                v1 = round(v1, readLittleEndian(bytes, index))
                v2 = round(v2, readLittleEndian(bytes, index + Int.SIZE_BYTES))
                v3 = round(v3, readLittleEndian(bytes, index + 2 * Int.SIZE_BYTES))
                v4 = round(v4, readLittleEndian(bytes, index + 3 * Int.SIZE_BYTES))
                index += STRIPE
            }
            converge(v1, v2, v3, v4)
        } else {
            seed + P5
        }
        hash += length
        while (end - index >= Int.SIZE_BYTES) {
            hash = tailWord(hash, readLittleEndian(bytes, index))
            index += Int.SIZE_BYTES
        }
        while (index < end) {
            hash = tailByte(hash, bytes[index++].toInt() and BYTE_MASK)
        }
        return avalanche(hash)
    }

    override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long =
        hashInt(bytes, offset, length).toLong() and INT_MASK

    override fun newDigest(): XxHash32Digest = XxHash32Digest(seed)

    private companion object {
        private const val BYTE_MASK: Int = 0xFF
        private const val INT_MASK: Long = 0xFFFF_FFFFL
    }
}
