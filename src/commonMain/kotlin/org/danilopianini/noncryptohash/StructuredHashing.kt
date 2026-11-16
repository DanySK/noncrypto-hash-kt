@file:OptIn(ExperimentalUnsignedTypes::class)

package org.danilopianini.noncryptohash

import kotlin.reflect.KClass
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.uuid.Uuid

/**
 * Absorbs a structured [value] so that, for values of the same type, different values produce different byte
 * streams. Hashing never fails: unknown types fall back to [toString].
 *
 * ## Encoding
 * Every value starts with a one-byte type tag, followed by its content as written by the raw [Digest.update]
 * methods (little-endian, UTF-8, see [Digest]).
 * Variable-length content is followed (not preceded) by its element count as an `Int`.
 * This way, `Iterable`s and `Sequence`s are hashed in a single pass, without knowing their size in advance,
 * and the encoding stays unambiguous, because it can be decoded backwards.
 * Tags and layout are part of the stability contract: changing them changes every structured hash.
 *
 * Rules are applied in this order:
 * 1. `null`;
 * 2. [Hashable] values, which hash themselves;
 * 3. final built-in types, never subject to registry lookup:
 *    - primitives and unsigned types: tag, then the raw value;
 *    - [String]: tag, UTF-8 bytes, then the number of UTF-16 chars;
 *    - primitive, unsigned, and object arrays: tag, elements, size;
 *    - [Pair], [Triple]: tag, then each component;
 *    - [Result]: tag, success flag, then either the value or the exception;
 *    - [Uuid]: tag, then 16 bytes (most significant `Long` first);
 *    - [Duration]: tag, whole seconds (`Long`), then nanoseconds (`Int`), without loss of precision;
 *    - [Instant]: tag, epoch seconds (`Long`), then nanoseconds of second (`Int`), without loss of precision;
 *    - [Regex]: tag, pattern, then option names sorted alphabetically
 *      (by name, as the set of available options differs across targets);
 * 4. the funnel of the [FunnelRegistry] in context for the value, if any;
 * 5. open built-in types:
 *    - other [CharSequence]s: same as [String];
 *    - [Enum]: tag, then the [Enum.ordinal]: reordering the enum constants changes the hash;
 *    - [KClass]: tag, then the [KClass.simpleName] (`qualifiedName` is not available on all targets):
 *      classes with the same simple name in different packages collide;
 *    - progressions ([IntRange], [LongRange], [CharRange], [UIntRange], [ULongRange],
 *      and their progression supertypes): a tag per element type, `first`, `last`, `step`, in constant time,
 *      without iterating over the elements;
 *    - [ClosedRange] and [ClosedFloatingPointRange]: tag, `start`, `endInclusive`;
 *    - [OpenEndRange]: tag, `start`, `endExclusive`;
 *    - all empty ranges and progressions hash the same, consistent with their `equals`;
 *    - [Map.Entry]: tag, key, value;
 *    - [Map]: tag, the entries in iteration order, size;
 *    - [Iterable] and [Sequence]: tag, the elements in iteration order, count;
 *    - [Throwable]: tag, simple class name, message (the cause and stack trace are ignored);
 * 6. anything else: tag, then [toString] hashed as a [String].
 *
 * ## Caveats
 * - Collections are hashed in iteration order. Unordered collections ([Set]s and [Map]s backed by hash tables)
 *   may iterate differently across targets or runs, and so produce different hashes for equal contents.
 *   Insertion-ordered collections (Kotlin's default `setOf`, `mapOf`, `mutableSetOf`, `mutableMapOf`) are safe.
 * - [Sequence]s are consumed: constrained-once sequences cannot be hashed twice, infinite ones never terminate.
 *   An [Iterator] is *not* consumed: it falls back to [toString].
 * - The [toString] fallback is only as stable as the [toString] of the type:
 *   - lambdas, function references, [Comparator]s, [Lazy] values (whose [toString] depends on initialization),
 *     [Iterator]s, and any class not overriding [toString] produce identity-based strings,
 *     which change across runs and targets;
 *   - data classes are deterministic, but [Double] and [Float] properties are formatted differently across
 *     targets (`1.0` is `"1.0"` on the JVM and `"1"` on JS), making their hash target-dependent.
 *   Implement [Hashable] or register a [Funnel] for such types.
 * - Cross-type collisions are avoided by the tags, except for the documented equivalences above
 *   (e.g., [String] and other [CharSequence]s, or all empty ranges).
 */
context(registry: FunnelRegistry)
fun Digest.updateValue(value: Any?): Digest = apply {
    when {
        value == null -> update(ValueTag.NULL)
        value is Hashable -> {
            update(ValueTag.CUSTOM)
            value.hashInto(this)
        }
        updateFinal(value) -> Unit
        else -> {
            val funnel = registry.funnelFor(value)
            if (funnel == null) {
                updateOpen(value)
            } else {
                update(ValueTag.CUSTOM)
                funnel.write(this, value)
            }
        }
    }
}

/**
 * Absorbs a structured [value], resolving custom types through [registry].
 * Equivalent to calling the context-parameter overload of [updateValue] within `with(registry) { ... }`:
 * see it for the encoding.
 */
fun Digest.updateValue(value: Any?, registry: FunnelRegistry): Digest = context(registry) { updateValue(value) }

/**
 * Hashes the final built-in types. Returns false if [value] is not one of them.
 */
context(registry: FunnelRegistry)
private fun Digest.updateFinal(value: Any): Boolean {
    when (value) {
        // Primitives
        is Boolean -> update(ValueTag.BOOLEAN).update(value)
        is Byte -> update(ValueTag.BYTE).update(value)
        is Short -> update(ValueTag.SHORT).update(value)
        is Int -> update(ValueTag.INT).update(value)
        is Long -> update(ValueTag.LONG).update(value)
        is Char -> update(ValueTag.CHAR).update(value)
        is Float -> update(ValueTag.FLOAT).update(value)
        is Double -> update(ValueTag.DOUBLE).update(value)
        is UByte -> update(ValueTag.UBYTE).update(value)
        is UShort -> update(ValueTag.USHORT).update(value)
        is UInt -> update(ValueTag.UINT).update(value)
        is ULong -> update(ValueTag.ULONG).update(value)
        // Strings
        is CharSequence -> updateText(value)
        is Regex -> {
            update(ValueTag.REGEX).updateText(value.pattern)
            val options = value.options.map { it.name }.sorted()
            options.forEach { updateText(it) }
            update(options.size)
        }
        // PrimitiveArrays
        is ByteArray -> update(ValueTag.BYTE_ARRAY).update(value).update(value.size)
        is BooleanArray -> update(ValueTag.BOOLEAN_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is ShortArray -> update(ValueTag.SHORT_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is IntArray -> update(ValueTag.INT_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is LongArray -> update(ValueTag.LONG_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is CharArray -> update(ValueTag.CHAR_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is FloatArray -> update(ValueTag.FLOAT_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is DoubleArray -> update(ValueTag.DOUBLE_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is UByteArray -> update(ValueTag.UBYTE_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is UShortArray -> update(ValueTag.USHORT_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is UIntArray -> update(ValueTag.UINT_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        is ULongArray -> update(ValueTag.ULONG_ARRAY).apply { value.forEach { update(it) } }.update(value.size)
        // Arrays
        is Array<*> -> {
            update(ValueTag.ARRAY)
            value.forEach { updateValue(it) }
            update(value.size)
        }
        // Tuples
        is Pair<*, *> -> update(ValueTag.PAIR).updateValue(value.first).updateValue(value.second)
        is Triple<*, *, *> ->
            update(ValueTag.TRIPLE)
                .updateValue(value.first)
                .updateValue(value.second)
                .updateValue(value.third)
        is Result<*> -> {
            update(ValueTag.RESULT).update(value.isSuccess)
            updateValue(value.getOrNull() ?: value.exceptionOrNull())
        }
        // Other Kotlin built-in types
        is Uuid -> {
            update(ValueTag.UUID)
            value.toLongs { mostSignificantBits, leastSignificantBits ->
                update(mostSignificantBits).update(leastSignificantBits)
            }
        }
        is Duration -> {
            update(ValueTag.DURATION)
            value.toComponents { seconds: Long, nanoseconds: Int -> update(seconds).update(nanoseconds) }
        }
        is Instant -> update(ValueTag.INSTANT).update(value.epochSeconds).update(value.nanosecondsOfSecond)
        else -> return false
    }
    return true
}

/**
 * Hashes the open built-in types, falling back to [toString].
 */
context(registry: FunnelRegistry)
private fun Digest.updateOpen(value: Any) {
    when (value) {
        is CharSequence -> updateText(value)
        is Enum<*> -> update(ValueTag.ENUM).update(value.ordinal)
        is KClass<*> -> update(ValueTag.KCLASS).updateValue(value.simpleName)
        is IntProgression -> updateRange(value.isEmpty(), ValueTag.INT_PROGRESSION) {
            update(value.first).update(value.last).update(value.step)
        }
        is LongProgression -> updateRange(value.isEmpty(), ValueTag.LONG_PROGRESSION) {
            update(value.first).update(value.last).update(value.step)
        }
        is CharProgression -> updateRange(value.isEmpty(), ValueTag.CHAR_PROGRESSION) {
            update(value.first).update(value.last).update(value.step)
        }
        is UIntProgression -> updateRange(value.isEmpty(), ValueTag.UINT_PROGRESSION) {
            update(value.first).update(value.last).update(value.step)
        }
        is ULongProgression -> updateRange(value.isEmpty(), ValueTag.ULONG_PROGRESSION) {
            update(value.first).update(value.last).update(value.step)
        }
        is ClosedRange<*> -> updateRange(value.isEmpty(), ValueTag.CLOSED_RANGE) {
            updateValue(value.start).updateValue(value.endInclusive)
        }
        is OpenEndRange<*> -> updateRange(value.isEmpty(), ValueTag.OPEN_END_RANGE) {
            updateValue(value.start).updateValue(value.endExclusive)
        }
        is Map.Entry<*, *> -> update(ValueTag.MAP_ENTRY)
            .updateValue(value.key)
            .updateValue(value.value)
        is Map<*, *> -> {
            update(ValueTag.MAP)
            value.forEach { (key, entryValue) -> updateValue(key).updateValue(entryValue) }
            update(value.size)
        }
        is Iterable<*> -> updateElements(ValueTag.ITERABLE, value.iterator())
        is Sequence<*> -> updateElements(ValueTag.SEQUENCE, value.iterator())
        is Throwable -> update(ValueTag.THROWABLE)
            .updateValue(value::class.simpleName)
            .updateValue(value.message)
        else -> update(ValueTag.TO_STRING).updateText(value.toString())
    }
}

private fun Digest.updateText(value: CharSequence): Digest = update(ValueTag.TEXT).update(value).update(value.length)

private inline fun Digest.updateRange(isEmpty: Boolean, tag: Byte, content: Digest.() -> Unit) {
    if (isEmpty) {
        update(ValueTag.EMPTY_RANGE)
    } else {
        update(tag)
        content()
    }
}

context(registry: FunnelRegistry)
private fun Digest.updateElements(tag: Byte, elements: Iterator<*>) {
    update(tag)
    var count = 0
    elements.forEach {
        updateValue(it)
        count++
    }
    update(count)
}
