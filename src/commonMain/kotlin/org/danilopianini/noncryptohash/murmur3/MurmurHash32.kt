package org.danilopianini.noncryptohash.murmur3

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.readIntLittleEndian
import org.danilopianini.noncryptohash.common.requireRange
import org.danilopianini.noncryptohash.murmur3.MurmurHash32Digest.Companion.BYTE_MASK
import org.danilopianini.noncryptohash.murmur3.MurmurHash32Digest.Companion.INT_MASK
import org.danilopianini.noncryptohash.murmur3.MurmurHash32Digest.Companion.finalize
import org.danilopianini.noncryptohash.murmur3.MurmurHash32Digest.Companion.mixBlock
import org.danilopianini.noncryptohash.murmur3.MurmurHash32Digest.Companion.mixK

/**
 * MurmurHash3, x86 32-bit variant (`MurmurHash3_x86_32` in the reference implementation by Austin Appleby).
 *
 * It uses 32-bit arithmetic only, so it is fast on targets where 64-bit integers are emulated, such as JavaScript.
 * It matches Guava's `murmur3_32_fixed` for every seed, and its older `murmur3_32` for byte arrays
 * and for text without supplementary characters (such as emoji).
 *
 * [Digest.digestLong][org.danilopianini.noncryptohash.Digest.digestLong] zero-extends the hash,
 * and [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns its 4 bytes big-endian:
 * the hexadecimal digits of the 32-bit value in their natural order,
 * and the reverse of Guava's `HashCode.asBytes()`.
 *
 * The one-shot byte array methods hash without allocating a digest.
 *
 * @property seed the seed of every digest created by [newDigest].
 */
class MurmurHash32(val seed: Int = 0) : HashFunction {
    override val bits: Int = MurmurHash32Digest.BITS

    override fun hashInt(bytes: ByteArray, offset: Int, length: Int): Int {
        requireRange(bytes, offset, length)
        var hash = seed
        val end = offset + length
        val blocksEnd = end - (length and TAIL_MASK)
        for (index in offset until blocksEnd step Int.SIZE_BYTES) {
            hash = mixBlock(hash, readIntLittleEndian(bytes, index))
        }
        var tail = 0
        for (index in end - 1 downTo blocksEnd) {
            tail = (tail shl Byte.SIZE_BITS) or (bytes[index].toInt() and BYTE_MASK)
        }
        return finalize(hash xor mixK(tail), length)
    }

    override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long =
        hashInt(bytes, offset, length).toLong() and INT_MASK

    override fun newDigest(): MurmurHash32Digest = MurmurHash32Digest(seed)

    private companion object {
        private const val TAIL_MASK: Int = 3
    }
}
