package org.danilopianini.noncryptohash.common

/**
 * Reads 4 bytes of [bytes], starting at [index], as a little-endian `Int`.
 */
internal fun readIntLittleEndian(bytes: ByteArray, index: Int): Int = (bytes[index].toInt() and BYTE_MASK) or
    ((bytes[index + 1].toInt() and BYTE_MASK) shl Byte.SIZE_BITS) or
    ((bytes[index + 2].toInt() and BYTE_MASK) shl (2 * Byte.SIZE_BITS)) or
    (bytes[index + 3].toInt() shl (3 * Byte.SIZE_BITS))

/**
 * Reads 8 bytes of [bytes], starting at [index], as a little-endian `Long`.
 */
internal fun readLongLittleEndian(bytes: ByteArray, index: Int): Long =
    (readIntLittleEndian(bytes, index).toLong() and INT_MASK) or
        (readIntLittleEndian(bytes, index + Int.SIZE_BYTES).toLong() shl Int.SIZE_BITS)

/**
 * Writes the 4 bytes of [value] into [destination], starting at [offset], big-endian.
 */
internal fun writeIntBigEndian(value: Int, destination: ByteArray, offset: Int) {
    for (byte in 0 until Int.SIZE_BYTES) {
        destination[offset + byte] = (value ushr ((Int.SIZE_BYTES - 1 - byte) * Byte.SIZE_BITS)).toByte()
    }
}

/**
 * Writes the 8 bytes of [value] into [destination], starting at [offset], big-endian.
 */
internal fun writeLongBigEndian(value: Long, destination: ByteArray, offset: Int) {
    for (byte in 0 until Long.SIZE_BYTES) {
        destination[offset + byte] = (value ushr ((Long.SIZE_BYTES - 1 - byte) * Byte.SIZE_BITS)).toByte()
    }
}

/**
 * Writes the 8 bytes of [value] into [destination], starting at [offset], little-endian.
 */
internal fun writeLongLittleEndian(value: Long, destination: ByteArray, offset: Int) {
    for (byte in 0 until Long.SIZE_BYTES) {
        destination[offset + byte] = (value ushr (byte * Byte.SIZE_BITS)).toByte()
    }
}

private const val BYTE_MASK: Int = 0xFF
private const val INT_MASK: Long = 0xFFFF_FFFFL
