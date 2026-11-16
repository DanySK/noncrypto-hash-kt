package org.danilopianini.noncryptohash

/**
 * A streaming, stateful hash computation. Instances are **not** thread-safe.
 *
 * The `update` methods are a *raw byte sink*: values are absorbed with no framing, type tags or length
 * information, so that results match the reference test vectors of each algorithm.
 * For example, `update("ab").update("c")` and `update("abc")` produce the same digest.
 * Use [updateValue] to hash structured values unambiguously.
 *
 * Byte layout, identical on every target:
 * - multi-byte integers are absorbed **little-endian**, using exactly their width
 *   (`Short`: 2 bytes, `Int`: 4, `Long`: 8, `Char`: 2 as a UTF-16 code unit);
 * - `Boolean` is a single byte, `1` or `0`;
 * - `Float` and `Double` are absorbed via [Float.toBits] and [Double.toBits]: all NaNs hash the same,
 *   while `0.0` and `-0.0` differ;
 * - unsigned types are absorbed as their signed counterparts of the same width;
 * - text is encoded as **UTF-8**, with no allocation;
 *   unpaired surrogates are replaced by U+FFFD (`EF BF BD`) on every target.
 *   For well-formed text this matches [String.encodeToByteArray].
 *   For malformed text, the JVM's `encodeToByteArray` writes `?` instead.
 *
 * Implementations must provide the [bits] property and the abstract members
 * ([update] for a single byte and for a byte range, [digestInto], [digestLong], and [reset]).
 * Every other member has a correct but slow default,
 * which implementations should override with faster versions where it matters.
 */
interface Digest {

    /**
     * Size of the digest, in bits (e.g., 32, 64, 128). Always a multiple of 8.
     */
    val bits: Int

    /**
     * Absorbs [length] bytes of [bytes], starting at [offset].
     */
    fun update(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): Digest

    /**
     * Absorbs a single byte.
     */
    fun update(value: Byte): Digest

    /**
     * Writes the `bits / 8` bytes of the digest into [destination], starting at [offset],
     * as the big-endian representation of the hash value (most significant byte first).
     * Does **not** modify the state: more data can be absorbed afterward.
     */
    fun digestInto(destination: ByteArray, offset: Int = 0)

    /**
     * The low 64 bits of the digest. For digests narrower than 64 bits, the value is zero-extended.
     * Does **not** modify the state.
     */
    fun digestLong(): Long

    /**
     * Restores the initial state (including the seed, if any).
     */
    fun reset(): Digest

    /**
     * The digest as a newly allocated array of `bits / 8` bytes. See [digestInto].
     */
    fun digest(): ByteArray = ByteArray(bits / Byte.SIZE_BITS).also { digestInto(it) }

    /**
     * The low 32 bits of the digest. Does **not** modify the state.
     */
    fun digestInt(): Int = digestLong().toInt()

    /**
     * Absorbs one byte: `1` for `true`, `0` for `false`.
     */
    fun update(value: Boolean): Digest = update(if (value) 1.toByte() else 0.toByte())

    /**
     * Absorbs 2 bytes, little-endian.
     */
    fun update(value: Short): Digest = update(value.toByte()).update((value.toInt() ushr Byte.SIZE_BITS).toByte())

    /**
     * Absorbs 4 bytes, little-endian.
     */
    fun update(value: Int): Digest = update(value.toShort()).update((value ushr Short.SIZE_BITS).toShort())

    /**
     * Absorbs 8 bytes, little-endian.
     */
    fun update(value: Long): Digest = update(value.toInt()).update((value ushr Int.SIZE_BITS).toInt())

    /**
     * Absorbs the UTF-16 code unit as 2 bytes, little-endian.
     */
    fun update(value: Char): Digest = update(value.code.toShort())

    /**
     * Absorbs [Float.toBits] (4 bytes, little-endian).
     */
    fun update(value: Float): Digest = update(value.toBits())

    /**
     * Absorbs [Double.toBits] (8 bytes, little-endian).
     */
    fun update(value: Double): Digest = update(value.toBits())

    /**
     * Absorbs 1 byte.
     */
    fun update(value: UByte): Digest = update(value.toByte())

    /**
     * Absorbs 2 bytes, little-endian.
     */
    fun update(value: UShort): Digest = update(value.toShort())

    /**
     * Absorbs 4 bytes, little-endian.
     */
    fun update(value: UInt): Digest = update(value.toInt())

    /**
     * Absorbs 8 bytes, little-endian.
     */
    fun update(value: ULong): Digest = update(value.toLong())

    /**
     * Absorbs the characters of [value] between [start] (inclusive) and [end] (exclusive), encoded as UTF-8,
     * with no allocation and no length information.
     */
    @Suppress("MagicNumber")
    fun update(value: CharSequence, start: Int = 0, end: Int = value.length): Digest {
        var index = start
        while (index < end) {
            val char = value[index++]
            val code = char.code
            when {
                code < 0x80 -> update(code.toByte())
                code < 0x800 -> {
                    update((0xC0 or (code ushr 6)).toByte())
                    update((0x80 or (code and 0x3F)).toByte())
                }
                char.isHighSurrogate() && index < end && value[index].isLowSurrogate() -> {
                    val codePoint = 0x10000 + ((code - 0xD800) shl 10) + (value[index++].code - 0xDC00)
                    update((0xF0 or (codePoint ushr 18)).toByte())
                    update((0x80 or ((codePoint ushr 12) and 0x3F)).toByte())
                    update((0x80 or ((codePoint ushr 6) and 0x3F)).toByte())
                    update((0x80 or (codePoint and 0x3F)).toByte())
                }
                char.isSurrogate() -> {
                    // Unpaired surrogate: U+FFFD REPLACEMENT CHARACTER
                    update(0xEF.toByte())
                    update(0xBF.toByte())
                    update(0xBD.toByte())
                }
                else -> {
                    update((0xE0 or (code ushr 12)).toByte())
                    update((0x80 or ((code ushr 6) and 0x3F)).toByte())
                    update((0x80 or (code and 0x3F)).toByte())
                }
            }
        }
        return this
    }
}
