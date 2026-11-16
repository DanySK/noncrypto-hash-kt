package org.danilopianini.noncryptohash.benchmarks

/**
 * A JSON value that is already serialized.
 */
internal class RawJson(val text: String) {
    override fun toString(): String = text
}

/**
 * Serializes a JSON object. Supports strings, booleans, numbers (non-finite ones become null), nulls,
 * and nested [RawJson] values.
 */
internal fun json(vararg members: Pair<String, Any?>): RawJson = RawJson(
    members.joinToString(prefix = "{", postfix = "}", separator = ",") { (key, value) ->
        "${quote(key)}:${serialize(value)}"
    },
)

private fun serialize(value: Any?): String = when (value) {
    null -> "null"
    is RawJson -> value.text
    is String -> quote(value)
    is Boolean, is Int, is Long -> value.toString()
    is Double -> if (value.isFinite()) value.toString() else "null"
    else -> error("Unsupported JSON value: $value")
}

@Suppress("MagicNumber") // Control characters below 0x20 must be escaped
private fun quote(text: String): String = buildString {
    append('"')
    text.forEach { char ->
        when {
            char == '"' || char == '\\' -> append('\\').append(char)
            char.code < 0x20 -> append("\\u").append(char.code.toString(16).padStart(4, '0'))
            else -> append(char)
        }
    }
    append('"')
}
