package org.danilopianini.noncryptohash.xxhash

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.common.LongLaneDigest
import org.danilopianini.noncryptohash.common.absorbInBlocks
import org.danilopianini.noncryptohash.common.requireRoom

/**
 * Streaming [XxHash64] with the given [seed].
 * Holds no buffer: the pending stripe is kept in four `Long`s.
 *
 * @property seed the seed restored by [reset].
 */
class XxHash64Digest(val seed: Long = 0) : LongLaneDigest() {
    private var acc1: Long = seed + P1 + P2
    private var acc2: Long = seed + P2
    private var acc3: Long = seed
    private var acc4: Long = seed - P1

    /*
     * Pending (not yet processed) bytes of the current 32-byte stripe, little-endian:
     * bytes 0-7 in lane1, bytes 8-15 in lane2, and so on.
     */
    private var lane1: Long = 0
    private var lane2: Long = 0
    private var lane3: Long = 0
    private var lane4: Long = 0
    private var buffered: Int = 0
    private var length: Long = 0

    override val bits: Int = BITS

    // Appends to the pending block, and processes it when it is complete
    override fun absorb(value: Long, width: Int) {
        val position = buffered
        val lane = position ushr LANE_SHIFT
        val shift = (position and LANE_MASK) * Byte.SIZE_BITS
        orPending(lane, value shl shift)
        // shift > 0 when the value crosses into the next lane, so the shift below is in 8..56
        val crosses = (position and LANE_MASK) + width > Long.SIZE_BYTES
        val spill = if (crosses) value ushr (Long.SIZE_BITS - shift) else 0
        val end = position + width
        if (end >= STRIPE) {
            acc1 = round(acc1, lane1)
            acc2 = round(acc2, lane2)
            acc3 = round(acc3, lane3)
            acc4 = round(acc4, lane4)
            lane1 = spill
            lane2 = 0
            lane3 = 0
            lane4 = 0
            buffered = end - STRIPE
        } else {
            if (crosses) {
                orPending(lane + 1, spill)
            }
            buffered = end
        }
        length += width
    }

    override fun digestInto(destination: ByteArray, offset: Int) {
        requireRoom(destination, offset, Long.SIZE_BYTES)
        val hash = digestLong()
        for (byte in 0 until Long.SIZE_BYTES) {
            destination[offset + byte] = (hash ushr ((Long.SIZE_BYTES - 1 - byte) * Byte.SIZE_BITS)).toByte()
        }
    }

    override fun digestLong(): Long {
        var hash = if (length >= STRIPE) converge(acc1, acc2, acc3, acc4) else seed + P5
        hash += length
        // The pending bytes are the tail: whole lanes first, then a half lane, then single bytes
        var lane = 0
        var remaining = buffered
        while (remaining >= Long.SIZE_BYTES) {
            hash = tailLane(hash, pending(lane++))
            remaining -= Long.SIZE_BYTES
        }
        var bytes = pending(lane)
        if (remaining >= Int.SIZE_BYTES) {
            hash = tailHalfLane(hash, bytes and INT_MASK)
            bytes = bytes ushr Int.SIZE_BITS
            remaining -= Int.SIZE_BYTES
        }
        repeat(remaining) {
            hash = tailByte(hash, bytes and BYTE_MASK)
            bytes = bytes ushr Byte.SIZE_BITS
        }
        return avalanche(hash)
    }

    override fun reset(): Digest = apply {
        acc1 = seed + P1 + P2
        acc2 = seed + P2
        acc3 = seed
        acc4 = seed - P1
        lane1 = 0
        lane2 = 0
        lane3 = 0
        lane4 = 0
        buffered = 0
        length = 0
    }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        absorbInBlocks(bytes, offset, length, STRIPE, { buffered != 0 }, { absorb(it.toLong(), 1) }) { start, end ->
            var a = acc1
            var b = acc2
            var c = acc3
            var d = acc4
            for (index in start until end step STRIPE) {
                a = round(a, readLong(bytes, index))
                b = round(b, readLong(bytes, index + Long.SIZE_BYTES))
                c = round(c, readLong(bytes, index + 2 * Long.SIZE_BYTES))
                d = round(d, readLong(bytes, index + 3 * Long.SIZE_BYTES))
            }
            acc1 = a
            acc2 = b
            acc3 = c
            acc4 = d
            this.length += end - start
        }
    }

    private fun orPending(lane: Int, bits: Long) {
        when (lane) {
            0 -> lane1 = lane1 or bits
            1 -> lane2 = lane2 or bits
            2 -> lane3 = lane3 or bits
            else -> lane4 = lane4 or bits
        }
    }

    private fun pending(lane: Int): Long = when (lane) {
        0 -> lane1
        1 -> lane2
        2 -> lane3
        else -> lane4
    }

    internal companion object {
        const val BITS: Int = 64
        const val STRIPE: Int = 32
        const val P1: Long = -0x61c8_864e_7a14_3579L // 0x9E3779B185EBCA87
        const val P2: Long = -0x3d4d_51c2_d82b_14b1L // 0xC2B2AE3D27D4EB4F
        const val P3: Long = 0x1656_67b1_9e37_79f9L
        const val P4: Long = -0x7a14_3588_3d4d_519dL // 0x85EBCA77C2B2AE63
        const val P5: Long = 0x27d4_eb2f_1656_67c5L
        const val BYTE_MASK: Long = 0xFF
        const val INT_MASK: Long = 0xFFFF_FFFFL
        private const val LANE_SHIFT: Int = 3
        private const val LANE_MASK: Int = 7
        private const val ROUND_ROTATION: Int = 31
        private const val TAIL_BYTE_ROTATION: Int = 11
        private const val TAIL_HALF_LANE_ROTATION: Int = 23
        private const val TAIL_LANE_ROTATION: Int = 27
        private const val AVALANCHE_SHIFT_1: Int = 33
        private const val AVALANCHE_SHIFT_2: Int = 29
        private const val AVALANCHE_SHIFT_3: Int = 32

        fun avalanche(value: Long): Long {
            var hash = value xor (value ushr AVALANCHE_SHIFT_1)
            hash *= P2
            hash = hash xor (hash ushr AVALANCHE_SHIFT_2)
            hash *= P3
            return hash xor (hash ushr AVALANCHE_SHIFT_3)
        }

        @Suppress("MagicNumber") // The accumulator rotations of the specification, used only here
        fun converge(acc1: Long, acc2: Long, acc3: Long, acc4: Long): Long {
            var hash = acc1.rotateLeft(1) + acc2.rotateLeft(7) + acc3.rotateLeft(12) + acc4.rotateLeft(18)
            hash = merge(hash, acc1)
            hash = merge(hash, acc2)
            hash = merge(hash, acc3)
            return merge(hash, acc4)
        }

        fun readInt(bytes: ByteArray, index: Int): Long {
            var result = 0L
            for (byte in Int.SIZE_BYTES - 1 downTo 0) {
                result = (result shl Byte.SIZE_BITS) or (bytes[index + byte].toLong() and BYTE_MASK)
            }
            return result
        }

        fun readLong(bytes: ByteArray, index: Int): Long {
            var result = 0L
            for (byte in Long.SIZE_BYTES - 1 downTo 0) {
                result = (result shl Byte.SIZE_BITS) or (bytes[index + byte].toLong() and BYTE_MASK)
            }
            return result
        }

        fun tailByte(hash: Long, byte: Long): Long = (hash xor byte * P5).rotateLeft(TAIL_BYTE_ROTATION) * P1

        fun tailHalfLane(hash: Long, halfLane: Long): Long =
            (hash xor halfLane * P1).rotateLeft(TAIL_HALF_LANE_ROTATION) * P2 + P3

        fun tailLane(hash: Long, lane: Long): Long = (hash xor round(0, lane)).rotateLeft(TAIL_LANE_ROTATION) * P1 + P4

        private fun merge(hash: Long, accumulator: Long): Long = (hash xor round(0, accumulator)) * P1 + P4

        fun round(accumulator: Long, input: Long): Long = (accumulator + input * P2).rotateLeft(ROUND_ROTATION) * P1
    }
}
