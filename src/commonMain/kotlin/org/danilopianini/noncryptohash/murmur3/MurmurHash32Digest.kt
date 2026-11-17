package org.danilopianini.noncryptohash.murmur3

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.common.IntLaneDigest
import org.danilopianini.noncryptohash.common.absorbInBlocks
import org.danilopianini.noncryptohash.common.readIntLittleEndian

/**
 * Streaming [MurmurHash32] with the given [seed].
 * Uses 32-bit arithmetic only, and holds no buffer: the pending block is kept in one `Int`.
 *
 * @property seed the seed restored by [reset].
 */
class MurmurHash32Digest(val seed: Int = 0) : IntLaneDigest() {
    private var hash: Int = seed

    // Pending (not yet processed) bytes of the current 4-byte block, little-endian
    private var pending: Int = 0
    private var buffered: Int = 0

    // The total length modulo 2^32, as in the reference implementation
    private var length: Int = 0

    // Appends to the pending block, and mixes it when it is complete
    override fun absorb(value: Int, width: Int) {
        val position = buffered
        val block = pending or (value shl (position * Byte.SIZE_BITS))
        val end = position + width
        if (end >= Int.SIZE_BYTES) {
            hash = mixBlock(hash, block)
            // position > 0 when the value crosses into the next block, so the shift is in 8..24
            pending = if (position == 0) 0 else value ushr ((Int.SIZE_BYTES - position) * Byte.SIZE_BITS)
            buffered = end - Int.SIZE_BYTES
        } else {
            pending = block
            buffered = end
        }
        length += width
    }

    // Mixing an empty tail is a no-op, so the pending bytes can be mixed unconditionally
    override fun digestInt(): Int = finalize(hash xor mixK(pending), length)

    override fun reset(): Digest = apply {
        hash = seed
        pending = 0
        buffered = 0
        length = 0
    }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        absorbInBlocks(bytes, offset, length, Int.SIZE_BYTES, { buffered != 0 }, { absorb(it, 1) }) { start, end ->
            var h = hash
            for (index in start until end step Int.SIZE_BYTES) {
                h = mixBlock(h, readIntLittleEndian(bytes, index))
            }
            hash = h
            this.length += end - start
        }
    }

    internal companion object {
        const val BITS: Int = 32
        const val BYTE_MASK: Int = 0xFF
        const val INT_MASK: Long = 0xFFFF_FFFFL
        private const val C1: Int = -0x3361_d2af // 0xcc9e2d51
        private const val C2: Int = 0x1b87_3593
        private const val FMIX1: Int = -0x7a14_3595 // 0x85ebca6b
        private const val FMIX2: Int = -0x3d4d_51cb // 0xc2b2ae35
        private const val FMIX_SHIFT_1: Int = 16
        private const val FMIX_SHIFT_2: Int = 13
        private const val K_ROTATION: Int = 15
        private const val H_ROTATION: Int = 13
        private const val M: Int = 5
        private const val N: Int = -0x19ab_949c // 0xe6546b64

        /**
         * Mixes the [length] into the [hash] and applies the final avalanche (`fmix32`).
         */
        fun finalize(hash: Int, length: Int): Int {
            var h = hash xor length
            h = h xor (h ushr FMIX_SHIFT_1)
            h *= FMIX1
            h = h xor (h ushr FMIX_SHIFT_2)
            h *= FMIX2
            return h xor (h ushr FMIX_SHIFT_1)
        }

        fun mixBlock(hash: Int, block: Int): Int = (hash xor mixK(block)).rotateLeft(H_ROTATION) * M + N

        fun mixK(k: Int): Int = (k * C1).rotateLeft(K_ROTATION) * C2
    }
}
