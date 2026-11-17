package org.danilopianini.noncryptohash.crc

import org.danilopianini.noncryptohash.HashFunction

/**
 * A reflected 32-bit CRC, either [Crc32] or [Crc32c].
 *
 * CRCs are checksums: they detect accidental changes, but distribute keys worse than hashes such as
 * [XxHash32][org.danilopianini.noncryptohash.xxhash.XxHash32].
 * This implementation reads 8 bytes at a time through 8 KiB of lookup tables per polynomial,
 * shared by every instance and digest.
 *
 * [Digest.digestLong][org.danilopianini.noncryptohash.Digest.digestLong] zero-extends the CRC
 * (as `Checksum.getValue()`), and [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns its 4 bytes
 * big-endian: formats that store the CRC little-endian (such as gzip) hold the same bytes in reverse order.
 *
 * The one-shot byte array methods hash without allocating a digest.
 */
sealed class Crc32Function : HashFunction {
    /**
     * The lookup tables of the polynomial.
     */
    internal abstract val table: Crc32Table

    final override val bits: Int = Int.SIZE_BITS

    final override fun hashInt(bytes: ByteArray, offset: Int, length: Int): Int = table.hash(bytes, offset, length)

    final override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long =
        table.hash(bytes, offset, length).toLong() and INT_MASK

    final override fun newDigest(): Crc32Digest = Crc32Digest(table)

    private companion object {
        private const val INT_MASK: Long = 0xFFFF_FFFFL
    }
}
