package org.danilopianini.noncryptohash.common

/**
 * The high 64 bits of the unsigned 128-bit product of [a] and [b] (the low 64 bits are `a * b`).
 * Common Kotlin has no 128-bit multiplication, so it combines four 32-bit products.
 */
internal fun multiplyHighUnsigned(a: Long, b: Long): Long {
    val aLow = a and INT_MASK
    val aHigh = a ushr Int.SIZE_BITS
    val bLow = b and INT_MASK
    val bHigh = b ushr Int.SIZE_BITS
    val lowHigh = aLow * bHigh
    val highLow = aHigh * bLow
    // Cannot overflow: (2^32 - 1)^2 + 2 * (2^32 - 1) = 2^64 - 1
    val cross = ((aLow * bLow) ushr Int.SIZE_BITS) + (highLow and INT_MASK) + lowHigh
    return aHigh * bHigh + (highLow ushr Int.SIZE_BITS) + (cross ushr Int.SIZE_BITS)
}

/**
 * The low 64 bits of the unsigned 128-bit product of [a] and [b], xor its high 64 bits.
 */
internal fun foldedMultiply(a: Long, b: Long): Long = (a * b) xor multiplyHighUnsigned(a, b)

/**
 * [value] with its bytes in reverse order.
 */
internal fun reverseBytes(value: Int): Int = (value shl THIRD_BYTE) or
    ((value and SECOND_BYTE_MASK) shl Byte.SIZE_BITS) or
    ((value ushr Byte.SIZE_BITS) and SECOND_BYTE_MASK) or
    (value ushr THIRD_BYTE)

/**
 * [value] with its bytes in reverse order.
 */
internal fun reverseBytes(value: Long): Long = (reverseBytes(value.toInt()).toLong() shl Int.SIZE_BITS) or
    (reverseBytes((value ushr Int.SIZE_BITS).toInt()).toLong() and INT_MASK)

private const val INT_MASK: Long = 0xFFFF_FFFFL
private const val SECOND_BYTE_MASK: Int = 0xFF00
private const val THIRD_BYTE: Int = 3 * Byte.SIZE_BITS
