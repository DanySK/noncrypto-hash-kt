package org.danilopianini.noncryptohash

/**
 * A type that knows how to feed itself into a [Digest].
 * It takes precedence over every built-in rule of [updateValue], and costs a single type check.
 *
 * Implementations should be consistent with `equals`: equal objects must write the same bytes.
 */
fun interface Hashable {

    /**
     * Writes this object into [digest].
     * Nested values should be written with the context-parameter [updateValue] (`digest.updateValue(nested)`),
     * which uses the [FunnelRegistry] in context.
     */
    context(registry: FunnelRegistry)
    fun hashInto(digest: Digest)
}
