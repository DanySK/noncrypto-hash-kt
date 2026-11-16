package org.danilopianini.noncryptohash.common

/**
 * Type tags written by [updateValue] before each value of the structured encoding.
 * Part of the stability contract: never renumber them, as it would change every structured hash.
 * New tags must be appended.
 *
 * Plain `const` values rather than an enum: they are inlined as literals at every use,
 * so writing a tag costs no field access or object initialization.
 */
internal object ValueTag {
    const val NULL: Byte = 0
    const val CUSTOM: Byte = 1
    const val BOOLEAN: Byte = 2
    const val BYTE: Byte = 3
    const val SHORT: Byte = 4
    const val INT: Byte = 5
    const val LONG: Byte = 6
    const val CHAR: Byte = 7
    const val FLOAT: Byte = 8
    const val DOUBLE: Byte = 9
    const val UBYTE: Byte = 10
    const val USHORT: Byte = 11
    const val UINT: Byte = 12
    const val ULONG: Byte = 13
    const val TEXT: Byte = 14
    const val BYTE_ARRAY: Byte = 15
    const val BOOLEAN_ARRAY: Byte = 16
    const val SHORT_ARRAY: Byte = 17
    const val INT_ARRAY: Byte = 18
    const val LONG_ARRAY: Byte = 19
    const val CHAR_ARRAY: Byte = 20
    const val FLOAT_ARRAY: Byte = 21
    const val DOUBLE_ARRAY: Byte = 22
    const val UBYTE_ARRAY: Byte = 23
    const val USHORT_ARRAY: Byte = 24
    const val UINT_ARRAY: Byte = 25
    const val ULONG_ARRAY: Byte = 26
    const val ARRAY: Byte = 27
    const val PAIR: Byte = 28
    const val TRIPLE: Byte = 29
    const val RESULT: Byte = 30
    const val UUID: Byte = 31
    const val DURATION: Byte = 32
    const val INSTANT: Byte = 33
    const val REGEX: Byte = 34
    const val ENUM: Byte = 35
    const val KCLASS: Byte = 36
    const val INT_PROGRESSION: Byte = 37
    const val LONG_PROGRESSION: Byte = 38
    const val CHAR_PROGRESSION: Byte = 39
    const val UINT_PROGRESSION: Byte = 40
    const val ULONG_PROGRESSION: Byte = 41
    const val CLOSED_RANGE: Byte = 42
    const val OPEN_END_RANGE: Byte = 43
    const val EMPTY_RANGE: Byte = 44
    const val MAP_ENTRY: Byte = 45
    const val MAP: Byte = 46
    const val ITERABLE: Byte = 47
    const val SEQUENCE: Byte = 48
    const val THROWABLE: Byte = 49
    const val TO_STRING: Byte = 50
}
