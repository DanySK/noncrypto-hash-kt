package org.danilopianini.noncryptohash.murmur3

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.requireRange
import org.danilopianini.noncryptohash.requireRoom

/**
 * Streaming [MurmurHash128] with the given [seed], zero-extended to 64 bits.
 * Holds no buffer: the pending block is kept in two `Long`s.
 *
 * @property seed the seed restored by [reset].
 */
class MurmurHash128Digest(val seed: Int = 0) : Digest {
    private var h1: Long = seed.toLong() and INT_MASK
    private var h2: Long = h1

    /*
     * Pending (not yet processed) bytes of the current 16-byte block, little-endian:
     * bytes 0-7 in k1, bytes 8-15 in k2.
     */
    private var k1: Long = 0
    private var k2: Long = 0
    private var buffered: Int = 0
    private var length: Long = 0

    override val bits: Int = BITS

    override fun digestInto(destination: ByteArray, offset: Int) {
        requireRoom(destination, offset, BYTES)
        finalize { high, low ->
            writeBigEndian(high, destination, offset)
            writeBigEndian(low, destination, offset + Long.SIZE_BYTES)
        }
    }

    override fun digestLong(): Long = finalize { _, low -> low }

    override fun reset(): Digest = apply {
        h1 = seed.toLong() and INT_MASK
        h2 = h1
        k1 = 0
        k2 = 0
        buffered = 0
        length = 0
    }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        requireRange(bytes, offset, length)
        var index = offset
        val end = offset + length
        // Complete the pending block, if any
        while (buffered != 0 && index < end) {
            absorb(bytes[index++].toLong() and BYTE_MASK, 1)
        }
        // Whole blocks, read directly from the array
        while (end - index >= BYTES) {
            mixBlock(readLittleEndian(bytes, index), readLittleEndian(bytes, index + Long.SIZE_BYTES))
            index += BYTES
            this.length += BYTES
        }
        // The tail goes into the pending block
        while (index < end) {
            absorb(bytes[index++].toLong() and BYTE_MASK, 1)
        }
    }

    override fun update(value: Byte): Digest = apply { absorb(value.toLong() and BYTE_MASK, Byte.SIZE_BYTES) }

    override fun update(value: Short): Digest = apply { absorb(value.toLong() and SHORT_MASK, Short.SIZE_BYTES) }

    override fun update(value: Int): Digest = apply { absorb(value.toLong() and INT_MASK, Int.SIZE_BYTES) }

    override fun update(value: Long): Digest = apply { absorb(value, Long.SIZE_BYTES) }

    /**
     * Appends the low [width] bytes of [value] (whose other bytes must be zero) to the pending block,
     * processing the block when it is complete.
     */
    private fun absorb(value: Long, width: Int) {
        val position = buffered
        if (position < Long.SIZE_BYTES) {
            k1 = k1 or (value shl (position * Byte.SIZE_BITS))
            if (position + width > Long.SIZE_BYTES) {
                // position > 0 here, so the shift is in 8..56
                k2 = value ushr ((Long.SIZE_BYTES - position) * Byte.SIZE_BITS)
            }
        } else {
            k2 = k2 or (value shl ((position - Long.SIZE_BYTES) * Byte.SIZE_BITS))
        }
        val end = position + width
        if (end >= BYTES) {
            mixBlock(k1, k2)
            val overflow = end - BYTES
            k1 = if (overflow == 0) 0 else value ushr ((width - overflow) * Byte.SIZE_BITS)
            k2 = 0
            buffered = overflow
        } else {
            buffered = end
        }
        length += width
    }

    /**
     * Computes the final value without modifying the state, and passes its halves to [result].
     */
    private inline fun <R> finalize(result: (high: Long, low: Long) -> R): R {
        // Tail: mixing a zero lane is a no-op, so both lanes can be mixed unconditionally
        var low = h1 xor mixK1(k1)
        var high = h2 xor mixK2(k2)
        low = low xor length
        high = high xor length
        low += high
        high += low
        low = fmix64(low)
        high = fmix64(high)
        low += high
        high += low
        return result(high, low)
    }

    private fun mixBlock(block1: Long, block2: Long) {
        h1 = h1 xor mixK1(block1)
        h1 = h1.rotateLeft(R1) + h2
        h1 = h1 * M + N1
        h2 = h2 xor mixK2(block2)
        h2 = h2.rotateLeft(R2) + h1
        h2 = h2 * M + N2
    }

    internal companion object {
        const val BITS: Int = 128
        private const val BYTES: Int = BITS / Byte.SIZE_BITS
        private const val BYTE_MASK: Long = 0xFF
        private const val SHORT_MASK: Long = 0xFFFF
        private const val INT_MASK: Long = 0xFFFF_FFFFL
        private const val C1: Long = -0x783c_846e_eebd_ac2bL // 0x87c37b91114253d5
        private const val C2: Long = 0x4cf5_ad43_2745_937fL
        private const val FMIX1: Long = -0x00ae_5028_12aa_7333L // 0xff51afd7ed558ccd
        private const val FMIX2: Long = -0x3b31_4601_e57a_13adL // 0xc4ceb9fe1a85ec53
        private const val FMIX_SHIFT: Int = 33
        private const val R1: Int = 27
        private const val R2: Int = 31
        private const val K1_ROTATION: Int = 31
        private const val K2_ROTATION: Int = 33
        private const val M: Long = 5
        private const val N1: Long = 0x52dc_e729
        private const val N2: Long = 0x3849_5ab5

        private fun fmix64(value: Long): Long {
            var k = value xor (value ushr FMIX_SHIFT)
            k *= FMIX1
            k = k xor (k ushr FMIX_SHIFT)
            k *= FMIX2
            return k xor (k ushr FMIX_SHIFT)
        }

        private fun mixK1(k: Long): Long = (k * C1).rotateLeft(K1_ROTATION) * C2

        private fun mixK2(k: Long): Long = (k * C2).rotateLeft(K2_ROTATION) * C1

        private fun readLittleEndian(bytes: ByteArray, index: Int): Long {
            var result = 0L
            for (byte in Long.SIZE_BYTES - 1 downTo 0) {
                result = (result shl Byte.SIZE_BITS) or (bytes[index + byte].toLong() and BYTE_MASK)
            }
            return result
        }

        private fun writeBigEndian(value: Long, destination: ByteArray, offset: Int) {
            for (byte in 0 until Long.SIZE_BYTES) {
                destination[offset + byte] = (value ushr ((Long.SIZE_BYTES - 1 - byte) * Byte.SIZE_BITS)).toByte()
            }
        }
    }
}
