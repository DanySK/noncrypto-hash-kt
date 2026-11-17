package org.danilopianini.noncryptohash.fnv

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.common.IntLaneDigest
import org.danilopianini.noncryptohash.common.requireRange

/**
 * Streaming [Fnv1a32]. Its whole state is the 32-bit hash.
 */
class Fnv1a32Digest : IntLaneDigest() {
    private var hash: Int = OFFSET_BASIS

    override fun absorb(value: Int, width: Int) {
        var h = hash
        var rest = value
        repeat(width) {
            h = (h xor (rest and BYTE_MASK)) * PRIME
            rest = rest ushr Byte.SIZE_BITS
        }
        hash = h
    }

    override fun digestInt(): Int = hash

    override fun reset(): Digest = apply { hash = OFFSET_BASIS }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        requireRange(bytes, offset, length)
        hash = absorbBytes(hash, bytes, offset, offset + length)
    }

    internal companion object {
        const val OFFSET_BASIS: Int = -0x7ee3_623b // 0x811c9dc5
        private const val PRIME: Int = 0x0100_0193
        private const val BYTE_MASK: Int = 0xFF

        /**
         * The [hash] after absorbing the bytes of [bytes] from [start] (inclusive) to [end] (exclusive).
         */
        fun absorbBytes(hash: Int, bytes: ByteArray, start: Int, end: Int): Int {
            var h = hash
            for (index in start until end) {
                h = (h xor (bytes[index].toInt() and BYTE_MASK)) * PRIME
            }
            return h
        }
    }
}
