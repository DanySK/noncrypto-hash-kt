package org.danilopianini.noncryptohash.siphash

/*
 * The SipHash state transformations, shared by the one-shot methods and the digest.
 * They pass the four state words to a callback instead of returning them, so that inlining avoids any allocation.
 */

/**
 * Applies [rounds] SipRounds to the state ([v0], [v1], [v2], [v3]), and passes the new state to [result].
 */
internal inline fun sipRounds(
    rounds: Int,
    v0: Long,
    v1: Long,
    v2: Long,
    v3: Long,
    result: (v0: Long, v1: Long, v2: Long, v3: Long) -> Unit,
) {
    var a = v0
    var b = v1
    var c = v2
    var d = v3
    repeat(rounds) {
        a += b
        b = b.rotateLeft(ROTATION_B1) xor a
        a = a.rotateLeft(HALF)
        c += d
        d = d.rotateLeft(ROTATION_D1) xor c
        a += d
        d = d.rotateLeft(ROTATION_D2) xor a
        c += b
        b = b.rotateLeft(ROTATION_B2) xor c
        c = c.rotateLeft(HALF)
    }
    result(a, b, c, d)
}

/**
 * Absorbs the [last] word (the final bytes, and the length modulo 256 in the top byte)
 * into the state ([v0], [v1], [v2], [v3]), and returns the finalized hash.
 */
internal fun sipFinish(
    v0: Long,
    v1: Long,
    v2: Long,
    v3: Long,
    last: Long,
    compressionRounds: Int,
    finalizationRounds: Int,
): Long {
    var hash = 0L
    sipRounds(compressionRounds, v0, v1, v2, v3 xor last) { a, b, c, d ->
        sipRounds(finalizationRounds, a xor last, b, c xor FINALIZATION, d) { e, f, g, h ->
            hash = e xor f xor g xor h
        }
    }
    return hash
}

/**
 * The bits of the length in the last word: its lowest byte, in the top byte of the word.
 */
internal fun lengthBits(length: Long): Long = length shl LENGTH_SHIFT

internal const val INIT0: Long = 0x736f_6d65_7073_6575L // "somepseu"
internal const val INIT1: Long = 0x646f_7261_6e64_6f6dL // "dorandom"
internal const val INIT2: Long = 0x6c79_6765_6e65_7261L // "lygenera"
internal const val INIT3: Long = 0x7465_6462_7974_6573L // "tedbytes"
private const val FINALIZATION: Long = 0xFF
private const val LENGTH_SHIFT: Int = 56
private const val HALF: Int = 32
private const val ROTATION_B1: Int = 13
private const val ROTATION_B2: Int = 17
private const val ROTATION_D1: Int = 16
private const val ROTATION_D2: Int = 21
