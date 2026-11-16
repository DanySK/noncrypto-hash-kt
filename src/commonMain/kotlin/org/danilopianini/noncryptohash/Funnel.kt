package org.danilopianini.noncryptohash

/**
 * Writes values of type [T] into a [Digest].
 * Use it for types you do not own; for your own types, prefer implementing [Hashable].
 *
 * Implementations should be consistent with `equals`: equal objects must write the same bytes.
 */
fun interface Funnel<in T> {

    /**
     * Writes [value] into [digest].
     * Nested values should be written with the context-parameter [updateValue] (`digest.updateValue(nested)`),
     * which uses the [FunnelRegistry] in context.
     */
    context(registry: FunnelRegistry)
    fun write(digest: Digest, value: T)
}
