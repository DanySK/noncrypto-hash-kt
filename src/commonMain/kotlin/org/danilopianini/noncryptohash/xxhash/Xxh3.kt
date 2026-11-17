@file:Suppress("MagicNumber") // Secret offsets, shifts, and rotations of the specification, clearer as literals

package org.danilopianini.noncryptohash.xxhash

import org.danilopianini.noncryptohash.common.foldedMultiply
import org.danilopianini.noncryptohash.common.multiplyHighUnsigned
import org.danilopianini.noncryptohash.common.readIntLittleEndian
import org.danilopianini.noncryptohash.common.readLongLittleEndian
import org.danilopianini.noncryptohash.common.reverseBytes
import org.danilopianini.noncryptohash.common.writeLongLittleEndian
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.P1
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.P2
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.P3
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.P4
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.P5
import org.danilopianini.noncryptohash.xxhash.XxHash64Digest.Companion.avalanche as xxh64Avalanche

/*
 * The algorithms of XXH3 (64-bit) and XXH128, shared by the one-shot methods and the digests, as in the
 * specification and in the scalar code path of the reference implementation (libxxhash 0.8).
 *
 * Secrets are arrays of the little-endian 64-bit word starting at each byte offset of the 192-byte secret,
 * because the algorithms read them at unaligned offsets.
 * Functions that produce several values pass them to a callback, so that inlining avoids any allocation.
 */

/**
 * The length of a stripe, the unit of the long-input loop.
 */
internal const val XXH3_STRIPE: Int = 64

/**
 * The longest input hashed by the short-input algorithms.
 */
internal const val XXH3_MIDSIZE_MAX: Int = 240

private const val SECRET_SIZE: Int = 192
private const val STRIPES_PER_BLOCK: Int = (SECRET_SIZE - XXH3_STRIPE) / Long.SIZE_BYTES
private const val SCRAMBLE_OFFSET: Int = SECRET_SIZE - XXH3_STRIPE
private const val LAST_STRIPE_OFFSET: Int = SCRAMBLE_OFFSET - 7
private const val MERGE_OFFSET: Int = 11
private const val MERGE_HIGH_OFFSET: Int = SCRAMBLE_OFFSET - MERGE_OFFSET
private const val MIDSIZE_START_OFFSET: Int = 3
private const val MIDSIZE_LAST_OFFSET: Int = 136 - 17
private const val PRIME32_1: Long = 0x9E37_79B1L
private const val PRIME32_2: Long = 0x85EB_CA77L
private const val PRIME32_3: Long = 0xC2B2_AE3DL
private const val PRIME_MX1: Long = 0x1656_6791_9E37_79F9L
private const val PRIME_MX2: Long = -0x604d_e39a_e167_20dbL // 0x9FB21C651E98DF25
private const val INT_MASK: Long = 0xFFFF_FFFFL
private const val BYTE_MASK: Int = 0xFF

private val DEFAULT_SECRET_BYTES: ByteArray = (
    "b8fe6c3923a44bbe7c01812cf721ad1cded46de9839097db7240a4a4b7b3671fcb79e64eccc0e578825ad07dccff7221" +
        "b8084674f743248ee03590e6813a264c3c2852bb91c300cb88d0658b1b532ea371644897a20df94e3819ef46a9deacd8" +
        "a8fa763fe39c343ff9dcbbc7c70b4f1d8a51e04bcdb45931c89f7ec9d9787364eac5ac8334d3ebc3c581a0fffa1363eb" +
        "170ddd51b7f0da49d316552629d4689e2b16be587d47a1fc8ff8b8d17ad031ce45cb3a8f95160428afd7fbcabb4b407e"
    ).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/**
 * The default secret, used by the short-input algorithms with every seed, and by the long-input one with seed 0.
 */
internal val XXH3_DEFAULT_SECRET: LongArray = xxh3Secret(0)

/**
 * The secret of the long-input algorithm with the given [seed], derived from the default one.
 */
internal fun xxh3Secret(seed: Long): LongArray {
    val bytes = ByteArray(SECRET_SIZE)
    for (offset in 0 until SECRET_SIZE step 2 * Long.SIZE_BYTES) {
        writeLongLittleEndian(readLongLittleEndian(DEFAULT_SECRET_BYTES, offset) + seed, bytes, offset)
        val high = offset + Long.SIZE_BYTES
        writeLongLittleEndian(readLongLittleEndian(DEFAULT_SECRET_BYTES, high) - seed, bytes, high)
    }
    return LongArray(SECRET_SIZE - Long.SIZE_BYTES + 1) { readLongLittleEndian(bytes, it) }
}

/**
 * XXH3 (64-bit) of [length] bytes of [input] from [offset], with the given [seed]
 * and the [longSecret] derived from it.
 */
internal fun xxh3Hash64(input: ByteArray, offset: Int, length: Int, seed: Long, longSecret: LongArray): Long = when {
    length <= 16 -> hash64UpTo16(input, offset, length, seed)
    length <= 128 -> hash64UpTo128(input, offset, length, seed)
    length <= XXH3_MIDSIZE_MAX -> hash64UpTo240(input, offset, length, seed)
    else -> xxh3LongInput(input, offset, length, longSecret) { a0, a1, a2, a3, a4, a5, a6, a7 ->
        xxh3Finish64(a0, a1, a2, a3, a4, a5, a6, a7, longSecret, length.toLong())
    }
}

/**
 * XXH128 of [length] bytes of [input] from [offset], with the given [seed] and the [longSecret] derived from it.
 * Passes the low and high halves of the hash to [result].
 */
internal inline fun <R> xxh3Hash128(
    input: ByteArray,
    offset: Int,
    length: Int,
    seed: Long,
    longSecret: LongArray,
    result: (low: Long, high: Long) -> R,
): R = when {
    length <= 16 -> hash128UpTo16(input, offset, length, seed, result)
    length <= 128 -> hash128UpTo128(input, offset, length, seed, result)
    length <= XXH3_MIDSIZE_MAX -> hash128UpTo240(input, offset, length, seed, result)
    else -> xxh3LongInput(input, offset, length, longSecret) { a0, a1, a2, a3, a4, a5, a6, a7 ->
        xxh3Finish128(a0, a1, a2, a3, a4, a5, a6, a7, longSecret, length.toLong(), result)
    }
}

/**
 * The 64-bit hash of an input longer than [XXH3_MIDSIZE_MAX] bytes, from its final accumulators.
 */
internal fun xxh3Finish64(
    a0: Long,
    a1: Long,
    a2: Long,
    a3: Long,
    a4: Long,
    a5: Long,
    a6: Long,
    a7: Long,
    secret: LongArray,
    length: Long,
): Long = merge(a0, a1, a2, a3, a4, a5, a6, a7, secret, MERGE_OFFSET, length * P1)

/**
 * The 128-bit hash of an input longer than [XXH3_MIDSIZE_MAX] bytes, from its final accumulators.
 */
internal inline fun <R> xxh3Finish128(
    a0: Long,
    a1: Long,
    a2: Long,
    a3: Long,
    a4: Long,
    a5: Long,
    a6: Long,
    a7: Long,
    secret: LongArray,
    length: Long,
    result: (low: Long, high: Long) -> R,
): R = result(
    merge(a0, a1, a2, a3, a4, a5, a6, a7, secret, MERGE_OFFSET, length * P1),
    merge(a0, a1, a2, a3, a4, a5, a6, a7, secret, MERGE_HIGH_OFFSET, (length * P2).inv()),
)

/**
 * Runs the long-input loop on [length] bytes of [input] from [offset] (more than [XXH3_MIDSIZE_MAX]),
 * and passes the final accumulators to [result].
 */
internal inline fun <R> xxh3LongInput(
    input: ByteArray,
    offset: Int,
    length: Int,
    secret: LongArray,
    result: (Long, Long, Long, Long, Long, Long, Long, Long) -> R,
): R {
    // Every stripe that ends before the last byte, then the last 64 bytes
    val stripes = (length - 1) / XXH3_STRIPE
    return xxh3Stripes(
        PRIME32_3, P1, P2, P3, P4, PRIME32_2, P5, PRIME32_1,
        input, offset, stripes, 0, secret,
    ) { a0, a1, a2, a3, a4, a5, a6, a7 ->
        xxh3LastStripe(a0, a1, a2, a3, a4, a5, a6, a7, input, offset + length - XXH3_STRIPE, secret, result)
    }
}

/**
 * The initial accumulators of the long-input loop, passed to [result].
 */
internal inline fun <R> xxh3InitialAccumulators(result: (Long, Long, Long, Long, Long, Long, Long, Long) -> R): R =
    result(PRIME32_3, P1, P2, P3, P4, PRIME32_2, P5, PRIME32_1)

/**
 * Accumulates [count] stripes of [input] from [offset] into the accumulators,
 * starting at stripe [first] of a block, and scrambling them at the end of each block.
 * Passes the new accumulators to [result].
 */
internal inline fun <R> xxh3Stripes(
    a0: Long,
    a1: Long,
    a2: Long,
    a3: Long,
    a4: Long,
    a5: Long,
    a6: Long,
    a7: Long,
    input: ByteArray,
    offset: Int,
    count: Int,
    first: Int,
    secret: LongArray,
    result: (Long, Long, Long, Long, Long, Long, Long, Long) -> R,
): R {
    var b0 = a0
    var b1 = a1
    var b2 = a2
    var b3 = a3
    var b4 = a4
    var b5 = a5
    var b6 = a6
    var b7 = a7
    var stripe = first
    for (index in offset until offset + count * XXH3_STRIPE step XXH3_STRIPE) {
        val s = stripe * Long.SIZE_BYTES
        val d0 = readLongLittleEndian(input, index)
        val d1 = readLongLittleEndian(input, index + 8)
        val d2 = readLongLittleEndian(input, index + 16)
        val d3 = readLongLittleEndian(input, index + 24)
        val d4 = readLongLittleEndian(input, index + 32)
        val d5 = readLongLittleEndian(input, index + 40)
        val d6 = readLongLittleEndian(input, index + 48)
        val d7 = readLongLittleEndian(input, index + 56)
        b0 += d1 + multiplyHalves(d0 xor secret[s])
        b1 += d0 + multiplyHalves(d1 xor secret[s + 8])
        b2 += d3 + multiplyHalves(d2 xor secret[s + 16])
        b3 += d2 + multiplyHalves(d3 xor secret[s + 24])
        b4 += d5 + multiplyHalves(d4 xor secret[s + 32])
        b5 += d4 + multiplyHalves(d5 xor secret[s + 40])
        b6 += d7 + multiplyHalves(d6 xor secret[s + 48])
        b7 += d6 + multiplyHalves(d7 xor secret[s + 56])
        if (++stripe == STRIPES_PER_BLOCK) {
            b0 = scramble(b0, secret[SCRAMBLE_OFFSET])
            b1 = scramble(b1, secret[SCRAMBLE_OFFSET + 8])
            b2 = scramble(b2, secret[SCRAMBLE_OFFSET + 16])
            b3 = scramble(b3, secret[SCRAMBLE_OFFSET + 24])
            b4 = scramble(b4, secret[SCRAMBLE_OFFSET + 32])
            b5 = scramble(b5, secret[SCRAMBLE_OFFSET + 40])
            b6 = scramble(b6, secret[SCRAMBLE_OFFSET + 48])
            b7 = scramble(b7, secret[SCRAMBLE_OFFSET + 56])
            stripe = 0
        }
    }
    return result(b0, b1, b2, b3, b4, b5, b6, b7)
}

/**
 * The stripe of a block that follows [count] stripes starting at stripe [first].
 */
internal fun xxh3NextStripe(first: Int, count: Int): Int = (first + count) % STRIPES_PER_BLOCK

/**
 * Accumulates the last stripe of the input, at [offset] in [input], and passes the accumulators to [result].
 */
internal inline fun <R> xxh3LastStripe(
    a0: Long,
    a1: Long,
    a2: Long,
    a3: Long,
    a4: Long,
    a5: Long,
    a6: Long,
    a7: Long,
    input: ByteArray,
    offset: Int,
    secret: LongArray,
    result: (Long, Long, Long, Long, Long, Long, Long, Long) -> R,
): R {
    val d0 = readLongLittleEndian(input, offset)
    val d1 = readLongLittleEndian(input, offset + 8)
    val d2 = readLongLittleEndian(input, offset + 16)
    val d3 = readLongLittleEndian(input, offset + 24)
    val d4 = readLongLittleEndian(input, offset + 32)
    val d5 = readLongLittleEndian(input, offset + 40)
    val d6 = readLongLittleEndian(input, offset + 48)
    val d7 = readLongLittleEndian(input, offset + 56)
    val s = LAST_STRIPE_OFFSET
    return result(
        a0 + d1 + multiplyHalves(d0 xor secret[s]),
        a1 + d0 + multiplyHalves(d1 xor secret[s + 8]),
        a2 + d3 + multiplyHalves(d2 xor secret[s + 16]),
        a3 + d2 + multiplyHalves(d3 xor secret[s + 24]),
        a4 + d5 + multiplyHalves(d4 xor secret[s + 32]),
        a5 + d4 + multiplyHalves(d5 xor secret[s + 40]),
        a6 + d7 + multiplyHalves(d6 xor secret[s + 48]),
        a7 + d6 + multiplyHalves(d7 xor secret[s + 56]),
    )
}

private fun hash64UpTo16(input: ByteArray, offset: Int, length: Int, seed: Long): Long {
    val secret = XXH3_DEFAULT_SECRET
    return when {
        length > 8 -> {
            val low = readLongLittleEndian(input, offset) xor ((secret[24] xor secret[32]) + seed)
            val high = readLongLittleEndian(input, offset + length - 8) xor ((secret[40] xor secret[48]) - seed)
            avalanche(length + reverseBytes(low) + high + foldedMultiply(low, high))
        }
        length >= 4 -> {
            val keyed = readHalves(input, offset, length) xor ((secret[8] xor secret[16]) - mixSeed(seed))
            rrmxmx(keyed, length)
        }
        length > 0 -> xxh64Avalanche(
            combine(input, offset, length) xor (((secret[0] xor secret[4]) and INT_MASK) + seed),
        )
        else -> xxh64Avalanche(seed xor secret[56] xor secret[64])
    }
}

private fun hash64UpTo128(input: ByteArray, offset: Int, length: Int, seed: Long): Long {
    val secret = XXH3_DEFAULT_SECRET
    var acc = length * P1
    for (round in (length - 1) / 32 downTo 0) {
        acc += mix16(input, offset + 16 * round, secret, 32 * round, seed)
        acc += mix16(input, offset + length - 16 * (round + 1), secret, 32 * round + 16, seed)
    }
    return avalanche(acc)
}

private fun hash64UpTo240(input: ByteArray, offset: Int, length: Int, seed: Long): Long {
    val secret = XXH3_DEFAULT_SECRET
    var acc = length * P1
    for (round in 0 until 8) {
        acc += mix16(input, offset + 16 * round, secret, 16 * round, seed)
    }
    var accEnd = mix16(input, offset + length - 16, secret, MIDSIZE_LAST_OFFSET, seed)
    acc = avalanche(acc)
    for (round in 8 until length / 16) {
        accEnd += mix16(input, offset + 16 * round, secret, 16 * (round - 8) + MIDSIZE_START_OFFSET, seed)
    }
    return avalanche(acc + accEnd)
}

internal inline fun <R> hash128UpTo16(
    input: ByteArray,
    offset: Int,
    length: Int,
    seed: Long,
    result: (low: Long, high: Long) -> R,
): R {
    val secret = XXH3_DEFAULT_SECRET
    return when {
        length > 8 -> {
            val low = readLongLittleEndian(input, offset)
            var high = readLongLittleEndian(input, offset + length - 8)
            val keyed = low xor high xor ((secret[32] xor secret[40]) - seed)
            var mLow = keyed * P1 + ((length - 1).toLong() shl 54)
            var mHigh = multiplyHighUnsigned(keyed, P1)
            high = high xor ((secret[48] xor secret[56]) + seed)
            mHigh += high + (high and INT_MASK) * (PRIME32_2 - 1)
            mLow = mLow xor reverseBytes(mHigh)
            result(avalanche(mLow * P2), avalanche(multiplyHighUnsigned(mLow, P2) + mHigh * P2))
        }
        length >= 4 -> {
            val keyed = readHalves(input, offset, length, swapped = true) xor
                ((secret[16] xor secret[24]) + mixSeed(seed))
            val multiplier = P1 + (length shl 2)
            var mLow = keyed * multiplier
            val mHigh = multiplyHighUnsigned(keyed, multiplier) + (mLow shl 1)
            mLow = mLow xor (mHigh ushr 3)
            mLow = (mLow xor (mLow ushr 35)) * PRIME_MX2
            result(mLow xor (mLow ushr 28), avalanche(mHigh))
        }
        length > 0 -> {
            val combined = combine(input, offset, length)
            val swapped = reverseBytes(combined.toInt()).rotateLeft(13).toLong() and INT_MASK
            result(
                xxh64Avalanche(combined xor (((secret[0] xor secret[4]) and INT_MASK) + seed)),
                xxh64Avalanche(swapped xor (((secret[8] xor secret[12]) and INT_MASK) - seed)),
            )
        }
        else -> result(
            xxh64Avalanche(seed xor secret[64] xor secret[72]),
            xxh64Avalanche(seed xor secret[80] xor secret[88]),
        )
    }
}

internal inline fun <R> hash128UpTo128(
    input: ByteArray,
    offset: Int,
    length: Int,
    seed: Long,
    result: (low: Long, high: Long) -> R,
): R {
    val secret = XXH3_DEFAULT_SECRET
    var low = length * P1
    var high = 0L
    for (round in (length - 1) / 32 downTo 0) {
        val first = offset + 16 * round
        val second = offset + length - 16 * (round + 1)
        low = (low + mix16(input, first, secret, 32 * round, seed)) xor sum16(input, second)
        high = (high + mix16(input, second, secret, 32 * round + 16, seed)) xor sum16(input, first)
    }
    return finish128(low, high, length, seed, result)
}

internal inline fun <R> hash128UpTo240(
    input: ByteArray,
    offset: Int,
    length: Int,
    seed: Long,
    result: (low: Long, high: Long) -> R,
): R {
    val secret = XXH3_DEFAULT_SECRET
    var low = length * P1
    var high = 0L
    for (position in 32 until 160 step 32) {
        val first = offset + position - 32
        val second = offset + position - 16
        low = (low + mix16(input, first, secret, position - 32, seed)) xor sum16(input, second)
        high = (high + mix16(input, second, secret, position - 16, seed)) xor sum16(input, first)
    }
    low = avalanche(low)
    high = avalanche(high)
    for (position in 160..length step 32) {
        val first = offset + position - 32
        val second = offset + position - 16
        val secretOffset = MIDSIZE_START_OFFSET + position - 160
        low = (low + mix16(input, first, secret, secretOffset, seed)) xor sum16(input, second)
        high = (high + mix16(input, second, secret, secretOffset + 16, seed)) xor sum16(input, first)
    }
    val first = offset + length - 16
    val second = offset + length - 32
    val secretOffset = MIDSIZE_LAST_OFFSET - 16
    low = (low + mix16(input, first, secret, secretOffset, -seed)) xor sum16(input, second)
    high = (high + mix16(input, second, secret, secretOffset + 16, -seed)) xor sum16(input, first)
    return finish128(low, high, length, seed, result)
}

internal inline fun <R> finish128(low: Long, high: Long, length: Int, seed: Long, result: (Long, Long) -> R): R =
    result(avalanche(low + high), -avalanche(low * P1 + high * P4 + (length - seed) * P2))

internal fun avalanche(value: Long): Long {
    val hash = (value xor (value ushr 37)) * PRIME_MX1
    return hash xor (hash ushr 32)
}

/**
 * The bytes 1 to 3 of the input, and its length, combined into an unsigned 32-bit value.
 */
internal fun combine(input: ByteArray, offset: Int, length: Int): Long {
    val first = input[offset].toInt() and BYTE_MASK
    val middle = input[offset + (length shr 1)].toInt() and BYTE_MASK
    val last = input[offset + length - 1].toInt() and BYTE_MASK
    return ((first shl 16) or (middle shl 24) or last or (length shl 8)).toLong() and INT_MASK
}

private fun merge(
    a0: Long,
    a1: Long,
    a2: Long,
    a3: Long,
    a4: Long,
    a5: Long,
    a6: Long,
    a7: Long,
    secret: LongArray,
    offset: Int,
    start: Long,
): Long = avalanche(
    start + foldedMultiply(a0 xor secret[offset], a1 xor secret[offset + 8]) +
        foldedMultiply(a2 xor secret[offset + 16], a3 xor secret[offset + 24]) +
        foldedMultiply(a4 xor secret[offset + 32], a5 xor secret[offset + 40]) +
        foldedMultiply(a6 xor secret[offset + 48], a7 xor secret[offset + 56]),
)

internal fun mix16(input: ByteArray, offset: Int, secret: LongArray, secretOffset: Int, seed: Long): Long =
    foldedMultiply(
        readLongLittleEndian(input, offset) xor (secret[secretOffset] + seed),
        readLongLittleEndian(input, offset + 8) xor (secret[secretOffset + 8] - seed),
    )

/**
 * The seed of the 4 to 8-byte inputs: its low half, byte-reversed, is xored into its high half.
 */
internal fun mixSeed(seed: Long): Long = seed xor (reverseBytes(seed.toInt()).toLong() shl Int.SIZE_BITS)

internal fun multiplyHalves(value: Long): Long = (value and INT_MASK) * (value ushr Int.SIZE_BITS)

/**
 * The first and last 4 bytes of a 4 to 8-byte input as a 64-bit value:
 * the last ones in the low half, or in the high half if [swapped].
 */
internal fun readHalves(input: ByteArray, offset: Int, length: Int, swapped: Boolean = false): Long {
    val first = readIntLittleEndian(input, offset).toLong() and INT_MASK
    val last = readIntLittleEndian(input, offset + length - Int.SIZE_BYTES).toLong() and INT_MASK
    return if (swapped) first + (last shl Int.SIZE_BITS) else last + (first shl Int.SIZE_BITS)
}

private fun rrmxmx(value: Long, length: Int): Long {
    var hash = value xor value.rotateLeft(49) xor value.rotateLeft(24)
    hash *= PRIME_MX2
    hash = (hash xor ((hash ushr 35) + length)) * PRIME_MX2
    return hash xor (hash ushr 28)
}

private fun scramble(accumulator: Long, secret: Long): Long =
    (accumulator xor (accumulator ushr 47) xor secret) * PRIME32_1

internal fun sum16(input: ByteArray, offset: Int): Long =
    readLongLittleEndian(input, offset) + readLongLittleEndian(input, offset + 8)
