package org.danilopianini.noncryptohash.common

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.HashFunction

/**
 * A [Digest] for hashes that mix the total length in before the first block (such as MurmurHash2),
 * and hence cannot start before the input is complete.
 *
 * It keeps the whole input in a growing buffer, and hashes it one shot with [hashFunction] when digesting:
 * unlike the other digests, its memory grows with the input.
 * [hashFunction] must implement its one-shot methods without creating a digest, and have 32 or 64 bits.
 */
internal class BufferedDigest(private val hashFunction: HashFunction) : LongLaneDigest() {
    private var buffer: ByteArray = ByteArray(INITIAL_CAPACITY)
    private var size: Int = 0

    override val bits: Int = hashFunction.bits

    init {
        require(bits == Int.SIZE_BITS || bits == Long.SIZE_BITS) { "Only 32 and 64-bit hashes can be buffered" }
    }

    override fun absorb(value: Long, width: Int) {
        ensureRoom(width)
        for (byte in 0 until width) {
            buffer[size + byte] = (value ushr (byte * Byte.SIZE_BITS)).toByte()
        }
        size += width
    }

    override fun digestInto(destination: ByteArray, offset: Int) {
        requireRoom(destination, offset, bits / Byte.SIZE_BITS)
        if (bits == Int.SIZE_BITS) {
            writeIntBigEndian(digestInt(), destination, offset)
        } else {
            writeLongBigEndian(digestLong(), destination, offset)
        }
    }

    override fun digestInt(): Int = hashFunction.hashInt(buffer, 0, size)

    override fun digestLong(): Long = hashFunction.hashLong(buffer, 0, size)

    override fun reset(): Digest = apply { size = 0 }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        requireRange(bytes, offset, length)
        ensureRoom(length)
        bytes.copyInto(buffer, size, offset, offset + length)
        size += length
    }

    private fun ensureRoom(bytes: Int) {
        if (size + bytes > buffer.size) {
            buffer = buffer.copyOf(maxOf(buffer.size * 2, size + bytes))
        }
    }

    private companion object {
        private const val INITIAL_CAPACITY: Int = 64
    }
}
