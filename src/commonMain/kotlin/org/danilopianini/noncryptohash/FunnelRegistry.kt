package org.danilopianini.noncryptohash

import kotlin.reflect.KClass

/**
 * An immutable, thread-safe association between types and the [Funnel]s used by [updateValue].
 *
 * The registry is consulted only for values that are not handled by a *final* built-in rule
 * (primitives, strings, arrays, and other final types: see [updateValue]),
 * so hashing those never pays for a lookup.
 * Collections, ranges, enums, and the other open types can instead be overridden by registering a funnel.
 *
 * Resolution: a funnel registered for the exact class of the value wins;
 * otherwise, the most recently registered type the value is an instance of wins.
 * In both cases, later registrations take precedence, so [extend] can override existing funnels.
 *
 * Build one with [FunnelRegistry.build] and share it.
 */
class FunnelRegistry private constructor(private val ordered: List<Pair<KClass<*>, Funnel<Any?>>>) {
    private val exact: Map<KClass<*>, Funnel<Any?>> = ordered.toMap()

    /**
     * The registered types, in registration order.
     */
    val types: List<KClass<*>> get() = ordered.map { it.first }

    /**
     * A new registry with the funnels of this one, followed by those added in [configuration].
     */
    fun extend(configuration: Builder.() -> Unit): FunnelRegistry = Builder(ordered).apply(configuration).build()

    /**
     * The funnel for [value], or null if none applies.
     */
    fun funnelFor(value: Any): Funnel<Any>? = when {
        ordered.isEmpty() -> null
        else -> exact[value::class] ?: ordered.lastOrNull { (type, _) -> type.isInstance(value) }?.second
    }

    /**
     * Accumulates funnels for a [FunnelRegistry].
     */
    class Builder internal constructor(initial: List<Pair<KClass<*>, Funnel<Any?>>>) {
        private val funnels = initial.toMutableList()

        internal fun build() = FunnelRegistry(funnels.toList())

        /**
         * Registers [funnel] for [type] and its subtypes.
         */
        fun <T : Any> register(type: KClass<T>, funnel: Funnel<T>): Builder = apply {
            @Suppress("UNCHECKED_CAST") // Safe: funnelFor only returns this funnel for instances of type
            funnels += type to (funnel as Funnel<Any?>)
        }

        /**
         * Registers [funnel] for [T] and its subtypes.
         */
        inline fun <reified T : Any> register(funnel: Funnel<T>): Builder = register(T::class, funnel)
    }

    /**
     * Factory and the empty registry.
     */
    companion object {

        /**
         * A registry with no funnels.
         */
        val EMPTY: FunnelRegistry = FunnelRegistry(emptyList())

        /**
         * Builds a new registry.
         */
        fun build(configuration: Builder.() -> Unit): FunnelRegistry = EMPTY.extend(configuration)
    }
}
