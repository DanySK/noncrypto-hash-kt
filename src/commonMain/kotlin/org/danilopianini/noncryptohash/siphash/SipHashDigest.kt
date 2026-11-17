package org.danilopianini.noncryptohash.siphash

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.common.LongLaneDigest
import org.danilopianini.noncryptohash.common.absorbInBlocks
import org.danilopianini.noncryptohash.common.readLongLittleEndian
import org.danilopianini.noncryptohash.common.requireRoom
import org.danilopianini.noncryptohash.common.writeLongBigEndian

/**
 * Streaming [SipHashFunction] with the key ([k0], [k1]).
 * Holds no buffer: the pending block is kept in one `Long`.
 */
class SipHashDigest internal constructor(
    private val k0: Long,
    private val k1: Long,
    private val compressionRounds: Int,
    private val finalizationRounds: Int,
) : LongLaneDigest() {
    private var v0: Long = k0 xor INIT0
    private var v1: Long = k1 xor INIT1
    private var v2: Long = k0 xor INIT2
    private var v3: Long = k1 xor INIT3

    // Pending (not yet processed) bytes of the current 8-byte block, little-endian
    private var pending: Long = 0
    private var buffered: Int = 0

    // Only the lowest byte of the length enters the hash
    private var length: Int = 0

    override val bits: Int = Long.SIZE_BITS

    // Appends to the pending block, and compresses it when it is complete
    override fun absorb(value: Long, width: Int) {
        val position = buffered
        val block = pending or (value shl (position * Byte.SIZE_BITS))
        val end = position + width
        if (end >= Long.SIZE_BYTES) {
            compress(block)
            // position > 0 when the value crosses into the next block, so the shift is in 8..56
            pending = if (position == 0) 0 else value ushr ((Long.SIZE_BYTES - position) * Byte.SIZE_BITS)
            buffered = end - Long.SIZE_BYTES
        } else {
            pending = block
            buffered = end
        }
        length += width
    }

    override fun digestInto(destination: ByteArray, offset: Int) {
        requireRoom(destination, offset, Long.SIZE_BYTES)
        writeLongBigEndian(digestLong(), destination, offset)
    }

    override fun digestLong(): Long =
        sipFinish(v0, v1, v2, v3, lengthBits(length.toLong()) or pending, compressionRounds, finalizationRounds)

    override fun reset(): Digest = apply {
        v0 = k0 xor INIT0
        v1 = k1 xor INIT1
        v2 = k0 xor INIT2
        v3 = k1 xor INIT3
        pending = 0
        buffered = 0
        length = 0
    }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        absorbInBlocks(bytes, offset, length, BLOCK, { buffered != 0 }, { absorb(it.toLong(), 1) }) { start, end ->
            for (index in start until end step BLOCK) {
                compress(readLongLittleEndian(bytes, index))
            }
            this.length += end - start
        }
    }

    private fun compress(block: Long) {
        sipRounds(compressionRounds, v0, v1, v2, v3 xor block) { a, b, c, d ->
            v0 = a xor block
            v1 = b
            v2 = c
            v3 = d
        }
    }

    private companion object {
        private const val BLOCK: Int = Long.SIZE_BYTES
    }
}
