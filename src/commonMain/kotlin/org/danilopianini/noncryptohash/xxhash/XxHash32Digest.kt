package org.danilopianini.noncryptohash.xxhash

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.common.IntLaneDigest
import org.danilopianini.noncryptohash.common.absorbInBlocks
import org.danilopianini.noncryptohash.common.readIntLittleEndian

/**
 * Streaming [XxHash32] with the given [seed], read as an unsigned 32-bit integer.
 * Uses 32-bit arithmetic only, and holds no buffer: the pending stripe is kept in four `Int`s.
 *
 * @property seed the seed restored by [reset].
 */
class XxHash32Digest(val seed: Int = 0) : IntLaneDigest() {
    private var v1: Int = seed + P1 + P2
    private var v2: Int = seed + P2
    private var v3: Int = seed
    private var v4: Int = seed - P1

    /*
     * Pending (not yet processed) bytes of the current 16-byte stripe, little-endian:
     * bytes 0-3 in p1, bytes 4-7 in p2, and so on.
     */
    private var p1: Int = 0
    private var p2: Int = 0
    private var p3: Int = 0
    private var p4: Int = 0
    private var buffered: Int = 0

    // The total length modulo 2^32, as in the specification, and whether at least one stripe was processed
    private var length: Int = 0
    private var large: Boolean = false

    // Appends to the pending stripe, and processes it when it is complete
    override fun absorb(value: Int, width: Int) {
        val position = buffered
        val word = position ushr 2
        val shift = (position and WORD_MASK) * Byte.SIZE_BITS
        orPending(word, value shl shift)
        // shift > 0 when the value crosses into the next word, so the shift below is in 8..24
        val spill = if ((position and WORD_MASK) + width > Int.SIZE_BYTES) value ushr (Int.SIZE_BITS - shift) else 0
        val end = position + width
        if (end >= STRIPE) {
            v1 = round(v1, p1)
            v2 = round(v2, p2)
            v3 = round(v3, p3)
            v4 = round(v4, p4)
            large = true
            p1 = spill
            p2 = 0
            p3 = 0
            p4 = 0
            buffered = end - STRIPE
        } else {
            if (spill != 0) {
                orPending(word + 1, spill)
            }
            buffered = end
        }
        length += width
    }

    override fun digestInt(): Int {
        var hash = (if (large) converge(v1, v2, v3, v4) else seed + P5) + length
        // The pending bytes are the tail: whole words first, then single bytes
        val words = buffered ushr 2
        if (words > 0) {
            hash = tailWord(hash, p1)
        }
        if (words > 1) {
            hash = tailWord(hash, p2)
        }
        if (words > 2) {
            hash = tailWord(hash, p3)
        }
        var rest = pending(words)
        repeat(buffered and WORD_MASK) {
            hash = tailByte(hash, rest and BYTE_MASK)
            rest = rest ushr Byte.SIZE_BITS
        }
        return avalanche(hash)
    }

    override fun reset(): Digest = apply {
        v1 = seed + P1 + P2
        v2 = seed + P2
        v3 = seed
        v4 = seed - P1
        p1 = 0
        p2 = 0
        p3 = 0
        p4 = 0
        buffered = 0
        length = 0
        large = false
    }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        absorbInBlocks(bytes, offset, length, STRIPE, { buffered != 0 }, { absorb(it, 1) }) { start, end ->
            var a = v1
            var b = v2
            var c = v3
            var d = v4
            for (index in start until end step STRIPE) {
                a = round(a, readIntLittleEndian(bytes, index))
                b = round(b, readIntLittleEndian(bytes, index + Int.SIZE_BYTES))
                c = round(c, readIntLittleEndian(bytes, index + 2 * Int.SIZE_BYTES))
                d = round(d, readIntLittleEndian(bytes, index + 3 * Int.SIZE_BYTES))
            }
            v1 = a
            v2 = b
            v3 = c
            v4 = d
            large = true
            this.length += end - start
        }
    }

    // Fast path: whole words go directly to the pending stripe when it is word-aligned
    override fun update(value: Int): Digest = apply {
        if ((buffered and WORD_MASK) == 0) appendWord(value) else absorb(value, Int.SIZE_BYTES)
    }

    override fun update(value: Long): Digest = apply {
        val low = value.toInt()
        val high = (value ushr Int.SIZE_BITS).toInt()
        if ((buffered and WORD_MASK) == 0) {
            appendWord(low)
            appendWord(high)
        } else {
            absorb(low, Int.SIZE_BYTES)
            absorb(high, Int.SIZE_BYTES)
        }
    }

    /**
     * Appends a whole [word] when the pending bytes are word-aligned (the next word is still empty),
     * processing the stripe when it is complete.
     */
    private fun appendWord(word: Int) {
        if (buffered == STRIPE - Int.SIZE_BYTES) {
            v1 = round(v1, p1)
            v2 = round(v2, p2)
            v3 = round(v3, p3)
            v4 = round(v4, word)
            large = true
            p1 = 0
            p2 = 0
            p3 = 0
            buffered = 0
        } else {
            when (buffered) {
                0 -> p1 = word
                Int.SIZE_BYTES -> p2 = word
                else -> p3 = word
            }
            buffered += Int.SIZE_BYTES
        }
        length += Int.SIZE_BYTES
    }

    private fun orPending(word: Int, bits: Int) {
        when (word) {
            0 -> p1 = p1 or bits
            1 -> p2 = p2 or bits
            2 -> p3 = p3 or bits
            else -> p4 = p4 or bits
        }
    }

    private fun pending(word: Int): Int = when (word) {
        0 -> p1
        1 -> p2
        2 -> p3
        else -> p4
    }

    internal companion object {
        const val BITS: Int = 32
        const val STRIPE: Int = 16
        const val P1: Int = -0x61c8_864f // 0x9E3779B1
        const val P2: Int = -0x7a14_3589 // 0x85EBCA77
        const val P3: Int = -0x3d4d_51c3 // 0xC2B2AE3D
        const val P4: Int = 0x27d4_eb2f
        const val P5: Int = 0x1656_67b1
        private const val BYTE_MASK: Int = 0xFF
        private const val WORD_MASK: Int = 3
        private const val ROUND_ROTATION: Int = 13
        private const val TAIL_BYTE_ROTATION: Int = 11
        private const val TAIL_WORD_ROTATION: Int = 17
        private const val AVALANCHE_SHIFT_1: Int = 15
        private const val AVALANCHE_SHIFT_2: Int = 13
        private const val AVALANCHE_SHIFT_3: Int = 16

        fun avalanche(value: Int): Int {
            var hash = value xor (value ushr AVALANCHE_SHIFT_1)
            hash *= P2
            hash = hash xor (hash ushr AVALANCHE_SHIFT_2)
            hash *= P3
            return hash xor (hash ushr AVALANCHE_SHIFT_3)
        }

        @Suppress("MagicNumber") // The lane rotations of the specification, used only here
        fun converge(v1: Int, v2: Int, v3: Int, v4: Int): Int =
            v1.rotateLeft(1) + v2.rotateLeft(7) + v3.rotateLeft(12) + v4.rotateLeft(18)

        fun round(accumulator: Int, input: Int): Int = (accumulator + input * P2).rotateLeft(ROUND_ROTATION) * P1

        fun tailByte(hash: Int, byte: Int): Int = (hash + byte * P5).rotateLeft(TAIL_BYTE_ROTATION) * P1

        fun tailWord(hash: Int, word: Int): Int = (hash + word * P3).rotateLeft(TAIL_WORD_ROTATION) * P4
    }
}
