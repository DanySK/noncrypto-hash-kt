package org.danilopianini.noncryptohash.crc

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.common.IntLaneDigest
import org.danilopianini.noncryptohash.common.requireRange
import org.danilopianini.noncryptohash.crc.Crc32Table.Companion.INITIAL

/**
 * Streaming [Crc32] or [Crc32c]. Its whole state is the 32-bit CRC register;
 * the lookup tables are shared by every digest of the same polynomial.
 */
class Crc32Digest internal constructor(private val table: Crc32Table) : IntLaneDigest() {
    private var crc: Int = INITIAL

    override fun absorb(value: Int, width: Int) {
        var result = crc
        var rest = value
        repeat(width) {
            result = table.updateByte(result, rest)
            rest = rest ushr Byte.SIZE_BITS
        }
        crc = result
    }

    override fun digestInt(): Int = crc.inv()

    override fun reset(): Digest = apply { crc = INITIAL }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        requireRange(bytes, offset, length)
        crc = table.update(crc, bytes, offset, offset + length)
    }
}
