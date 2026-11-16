package org.danilopianini.noncryptohash

/**
 * A [Digest] that records every absorbed byte, to test encodings.
 */
class RecordingDigest : Digest {
    private val bytes = mutableListOf<Byte>()

    override val bits: Int = Long.SIZE_BITS

    val recorded: List<Byte> get() = bytes.toList()

    override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        for (index in offset until offset + length) {
            this.bytes += bytes[index]
        }
    }

    override fun update(value: Byte): Digest = apply { bytes += value }

    override fun digestInto(destination: ByteArray, offset: Int) {
        val value = digestLong()
        for (index in 0 until Long.SIZE_BYTES) {
            destination[offset + index] = (value ushr (Long.SIZE_BITS - Byte.SIZE_BITS * (index + 1))).toByte()
        }
    }

    override fun digestLong(): Long = bytes.fold(0L) { hash, byte -> hash * 31 + byte }

    override fun reset(): Digest = apply { bytes.clear() }
}

fun raw(block: Digest.() -> Unit): List<Byte> = RecordingDigest().apply(block).recorded

fun structured(value: Any?, registry: FunnelRegistry = FunnelRegistry.EMPTY): List<Byte> =
    RecordingDigest().also { it.updateValue(value, registry) }.recorded
