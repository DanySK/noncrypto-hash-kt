package org.danilopianini.noncryptohash.common

import org.danilopianini.noncryptohash.Digest

/**
 * A 32-bit [Digest] that packs its pending input in 32-bit lanes, as hashes with 32-bit arithmetic do.
 *
 * Every fixed-width update reaches [absorb] as zero-extended `Int`s, without going through bytes
 * (a `Long` as two `Int`s, low half first):
 * implementations only need to absorb up to 4 bytes at a time, to process byte arrays, and to compute [digestInt],
 * from which the other forms of the digest derive.
 */
abstract class IntLaneDigest : Digest {

    final override val bits: Int = Int.SIZE_BITS

    final override fun digestInto(destination: ByteArray, offset: Int) {
        requireRoom(destination, offset, Int.SIZE_BYTES)
        writeIntBigEndian(digestInt(), destination, offset)
    }

    /**
     * The 32-bit digest. Does **not** modify the state.
     */
    abstract override fun digestInt(): Int

    final override fun digestLong(): Long = digestInt().toLong() and INT_MASK

    final override fun update(value: Byte): Digest = apply { absorb(value.toInt() and BYTE_MASK, Byte.SIZE_BYTES) }

    final override fun update(value: Short): Digest = apply { absorb(value.toInt() and SHORT_MASK, Short.SIZE_BYTES) }

    /**
     * Absorbs [value] through [absorb]. Implementations may override it with a faster path, with the same result.
     */
    override fun update(value: Int): Digest = apply { absorb(value, Int.SIZE_BYTES) }

    /**
     * Absorbs [value] through [absorb], as two `Int`s, low half first.
     * Implementations may override it with a faster path, with the same result.
     */
    override fun update(value: Long): Digest = apply {
        absorb(value.toInt(), Int.SIZE_BYTES)
        absorb((value ushr Int.SIZE_BITS).toInt(), Int.SIZE_BYTES)
    }

    /**
     * Absorbs the low [width] bytes of [value] (between 1 and 4), little-endian.
     * The other bytes of [value] are zero.
     */
    protected abstract fun absorb(value: Int, width: Int)

    private companion object {
        private const val BYTE_MASK: Int = 0xFF
        private const val SHORT_MASK: Int = 0xFFFF
        private const val INT_MASK: Long = 0xFFFF_FFFFL
    }
}
