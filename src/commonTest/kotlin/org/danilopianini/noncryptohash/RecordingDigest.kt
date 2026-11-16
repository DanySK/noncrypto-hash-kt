package org.danilopianini.noncryptohash

/**
 * A [Digest] that records every absorbed byte, to test encodings.
 */
class RecordingDigest : Digest {
    override val bits: Int = Long.SIZE_BITS

    private val bytes = mutableListOf<Byte>()

    val recorded: List<Byte> get() = bytes.toList()

    override fun digestInto(destination: ByteArray, offset: Int) {
        val value = digestLong()
        for (index in 0 until Long.SIZE_BYTES) {
            destination[offset + index] = (value ushr (Long.SIZE_BITS - Byte.SIZE_BITS * (index + 1))).toByte()
        }
    }

    override fun digestLong(): Long = bytes.fold(0L) { hash, byte -> hash * 31 + byte }

    override fun reset(): Digest = apply { bytes.clear() }

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        for (index in offset until offset + length) {
            this.bytes += bytes[index]
        }
    }

    override fun update(value: Byte): Digest = apply { bytes += value }
}

fun raw(block: Digest.() -> Unit): List<Byte> = RecordingDigest().apply(block).recorded

fun structured(value: Any?, registry: FunnelRegistry = FunnelRegistry.EMPTY): List<Byte> =
    RecordingDigest().also { it.updateValue(value, registry) }.recorded
