package org.danilopianini.noncryptohash

import org.danilopianini.noncryptohash.common.updateValue

/**
 * A stateless hash algorithm, configured once (e.g., with a seed) and safe to share across threads.
 *
 * The one-shot methods have default implementations based on [newDigest].
 * Implementations should override them with versions that skip the streaming machinery:
 * for short inputs, this is usually the fastest way to compute a hash.
 */
interface HashFunction {

    /**
     * Size of the produced digests, in bits.
     */
    val bits: Int

    /**
     * Hashes [length] bytes of [bytes], starting at [offset]. See [Digest.digestInt].
     */
    fun hashInt(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): Int =
        hashLong(bytes, offset, length).toInt()

    /**
     * Hashes the UTF-8 encoding of [value]. See [Digest.digestInt].
     */
    fun hashInt(value: CharSequence): Int = hashLong(value).toInt()

    /**
     * Hashes [length] bytes of [bytes], starting at [offset]. See [Digest.digestLong].
     */
    fun hashLong(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): Long =
        newDigest().update(bytes, offset, length).digestLong()

    /**
     * Hashes the UTF-8 encoding of [value]. See [Digest.update] and [Digest.digestLong].
     */
    fun hashLong(value: CharSequence): Long = newDigest().update(value).digestLong()

    /**
     * Hashes a structured [value] (see [updateValue]), resolving custom types through [registry].
     */
    fun hashValueInt(value: Any?, registry: FunnelRegistry = FunnelRegistry.EMPTY): Int =
        hashValueLong(value, registry).toInt()

    /**
     * Hashes a structured [value] (see [updateValue]), resolving custom types through [registry].
     */
    fun hashValueLong(value: Any?, registry: FunnelRegistry = FunnelRegistry.EMPTY): Long =
        newDigest().updateValue(value, registry).digestLong()

    /**
     * A new streaming [Digest] in its initial state.
     */
    fun newDigest(): Digest
}
