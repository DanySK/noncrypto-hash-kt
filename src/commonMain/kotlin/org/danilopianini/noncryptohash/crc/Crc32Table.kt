package org.danilopianini.noncryptohash.crc

import org.danilopianini.noncryptohash.common.readIntLittleEndian
import org.danilopianini.noncryptohash.common.requireRange

/**
 * The slicing-by-8 lookup tables (8 KiB) of a reflected 32-bit CRC with the given [polynomial], in reflected form.
 * Table `k` holds the CRC of each byte followed by `k` zero bytes, so that 8 bytes take 8 independent lookups.
 *
 * The CRC register is kept without the final inversion: it starts at [INITIAL], and is inverted when digesting.
 */
internal class Crc32Table(polynomial: Int) {
    private val table = IntArray(SLICES * TABLE_SIZE)

    init {
        for (byte in 0 until TABLE_SIZE) {
            var crc = byte
            repeat(Byte.SIZE_BITS) {
                crc = if ((crc and 1) != 0) (crc ushr 1) xor polynomial else crc ushr 1
            }
            table[byte] = crc
        }
        for (slice in 1 until SLICES) {
            for (byte in 0 until TABLE_SIZE) {
                val previous = table[(slice - 1) * TABLE_SIZE + byte]
                table[slice * TABLE_SIZE + byte] = (previous ushr Byte.SIZE_BITS) xor table[previous and BYTE_MASK]
            }
        }
    }

    /**
     * The CRC of [length] bytes of [bytes], starting at [offset].
     */
    fun hash(bytes: ByteArray, offset: Int, length: Int): Int {
        requireRange(bytes, offset, length)
        return update(INITIAL, bytes, offset, offset + length).inv()
    }

    /**
     * The register [crc] after the bytes of [bytes] from [start] (inclusive) to [end] (exclusive).
     */
    fun update(crc: Int, bytes: ByteArray, start: Int, end: Int): Int {
        var result = crc
        var index = start
        val slicesEnd = start + (end - start) / SLICES * SLICES
        while (index < slicesEnd) {
            val low = readIntLittleEndian(bytes, index) xor result
            val high = readIntLittleEndian(bytes, index + Int.SIZE_BYTES)
            result = table[T7 + (low and BYTE_MASK)] xor
                table[T6 + ((low ushr Byte.SIZE_BITS) and BYTE_MASK)] xor
                table[T5 + ((low ushr SECOND_SHIFT) and BYTE_MASK)] xor
                table[T4 + (low ushr THIRD_SHIFT)] xor
                table[T3 + (high and BYTE_MASK)] xor
                table[T2 + ((high ushr Byte.SIZE_BITS) and BYTE_MASK)] xor
                table[T1 + ((high ushr SECOND_SHIFT) and BYTE_MASK)] xor
                table[high ushr THIRD_SHIFT]
            index += SLICES
        }
        while (index < end) {
            result = updateByte(result, bytes[index++].toInt())
        }
        return result
    }

    /**
     * The register [crc] after the lowest byte of [byte] (the other bits are ignored).
     */
    fun updateByte(crc: Int, byte: Int): Int = (crc ushr Byte.SIZE_BITS) xor table[(crc xor byte) and BYTE_MASK]

    companion object {
        const val INITIAL: Int = -1
        private const val SLICES: Int = 8
        private const val TABLE_SIZE: Int = 256
        private const val T1: Int = TABLE_SIZE
        private const val T2: Int = 2 * TABLE_SIZE
        private const val T3: Int = 3 * TABLE_SIZE
        private const val T4: Int = 4 * TABLE_SIZE
        private const val T5: Int = 5 * TABLE_SIZE
        private const val T6: Int = 6 * TABLE_SIZE
        private const val T7: Int = 7 * TABLE_SIZE
        private const val SECOND_SHIFT: Int = 2 * Byte.SIZE_BITS
        private const val THIRD_SHIFT: Int = 3 * Byte.SIZE_BITS
        private const val BYTE_MASK: Int = 0xFF
    }
}
