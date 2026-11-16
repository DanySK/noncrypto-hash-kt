package org.danilopianini.noncryptohash.common

import org.danilopianini.noncryptohash.Digest

/**
 * A [Digest] that packs its pending input in 64-bit lanes, as most hashes with 64-bit arithmetic do.
 *
 * Every fixed-width update reaches [absorb] as a single zero-extended `Long`, without going through bytes:
 * implementations only need to absorb up to 8 bytes at a time, and to process byte arrays.
 */
abstract class LongLaneDigest : Digest {

    final override fun update(value: Byte): Digest = apply { absorb(value.toLong() and BYTE_MASK, Byte.SIZE_BYTES) }

    final override fun update(value: Short): Digest = apply {
        absorb(value.toLong() and SHORT_MASK, Short.SIZE_BYTES)
    }

    final override fun update(value: Int): Digest = apply { absorb(value.toLong() and INT_MASK, Int.SIZE_BYTES) }

    final override fun update(value: Long): Digest = apply { absorb(value, Long.SIZE_BYTES) }

    /**
     * Absorbs the low [width] bytes of [value] (between 1 and 8), little-endian.
     * The other bytes of [value] are zero.
     */
    protected abstract fun absorb(value: Long, width: Int)

    private companion object {
        private const val BYTE_MASK: Long = 0xFF
        private const val SHORT_MASK: Long = 0xFFFF
        private const val INT_MASK: Long = 0xFFFF_FFFFL
    }
}
