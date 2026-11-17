package org.danilopianini.noncryptohash.fnv

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.common.LongLaneDigest
import org.danilopianini.noncryptohash.common.requireRange
import org.danilopianini.noncryptohash.common.requireRoom
import org.danilopianini.noncryptohash.common.writeLongBigEndian

/**
 * Streaming [Fnv1a64]. Its whole state is the 64-bit hash.
 */
class Fnv1a64Digest : LongLaneDigest() {
    private var hash: Long = OFFSET_BASIS

    override val bits: Int = Long.SIZE_BITS

    override fun absorb(value: Long, width: Int) {
        var h = hash
        var rest = value
        repeat(width) {
            h = (h xor (rest and BYTE_MASK)) * PRIME
            rest = rest ushr Byte.SIZE_BITS
        }
        hash = h
    }

    override fun digestInto(destination: ByteArray, offset: Int) {
        requireRoom(destination, offset, Long.SIZE_BYTES)
        writeLongBigEndian(hash, destination, offset)
    }

    override fun digestLong(): Long = hash

    override fun reset(): Digest = apply { hash = OFFSET_BASIS }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        requireRange(bytes, offset, length)
        hash = absorbBytes(hash, bytes, offset, offset + length)
    }

    internal companion object {
        const val OFFSET_BASIS: Long = -0x340d_631b_7bdd_dcdbL // 0xcbf29ce484222325
        private const val PRIME: Long = 0x100_0000_01b3L
        private const val BYTE_MASK: Long = 0xFF

        /**
         * The [hash] after absorbing the bytes of [bytes] from [start] (inclusive) to [end] (exclusive).
         */
        fun absorbBytes(hash: Long, bytes: ByteArray, start: Int, end: Int): Long {
            var h = hash
            for (index in start until end) {
                h = (h xor (bytes[index].toLong() and BYTE_MASK)) * PRIME
            }
            return h
        }
    }
}
