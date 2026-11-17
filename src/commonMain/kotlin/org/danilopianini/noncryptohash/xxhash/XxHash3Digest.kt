package org.danilopianini.noncryptohash.xxhash

import org.danilopianini.noncryptohash.common.BlockBufferDigest
import org.danilopianini.noncryptohash.common.requireRoom
import org.danilopianini.noncryptohash.common.writeLongBigEndian

/**
 * Streaming [XxHash3] (64 [bits]) or [XxHash128] (128 [bits]).
 *
 * XXH3 hashes inputs of up to 240 bytes as a whole, and ends long inputs with their last 64 bytes, even if they
 * overlap stripes already processed: the digest keeps up to 256 pending bytes (4 stripes),
 * preceded by the last 64 bytes processed.
 */
class XxHash3Digest internal constructor(
    private val seed: Long,
    private val secret: LongArray,
    override val bits: Int,
) : BlockBufferDigest(CAPACITY, XXH3_STRIPE) {
    private var a0: Long = 0
    private var a1: Long = 0
    private var a2: Long = 0
    private var a3: Long = 0
    private var a4: Long = 0
    private var a5: Long = 0
    private var a6: Long = 0
    private var a7: Long = 0

    // The stripe of the current block that comes next
    private var stripe: Int = 0

    init {
        resetBlocks()
    }

    override fun digestInto(destination: ByteArray, offset: Int) {
        requireRoom(destination, offset, bits / Byte.SIZE_BITS)
        if (bits == Long.SIZE_BITS) {
            writeLongBigEndian(digestLong(), destination, offset)
        } else {
            finish128 { low, high ->
                writeLongBigEndian(high, destination, offset)
                writeLongBigEndian(low, destination, offset + Long.SIZE_BYTES)
            }
        }
    }

    override fun digestLong(): Long = when {
        bits != Long.SIZE_BITS -> finish128 { low, _ -> low }
        length <= XXH3_MIDSIZE_MAX -> xxh3Hash64(buffer, XXH3_STRIPE, buffered, seed, secret)
        else -> finishLong { b0, b1, b2, b3, b4, b5, b6, b7 ->
            xxh3Finish64(b0, b1, b2, b3, b4, b5, b6, b7, secret, length)
        }
    }

    override fun processBlocks(input: ByteArray, offset: Int, count: Int) {
        val stripes = count * STRIPES_PER_BLOCK
        xxh3Stripes(a0, a1, a2, a3, a4, a5, a6, a7, input, offset, stripes, stripe, secret, ::store)
        stripe = xxh3NextStripe(stripe, stripes)
    }

    override fun resetBlocks() {
        xxh3InitialAccumulators(::store)
        stripe = 0
    }

    /**
     * Passes the low and high halves of the 128-bit hash to [result].
     */
    private inline fun <R> finish128(result: (low: Long, high: Long) -> R): R = when {
        length <= XXH3_MIDSIZE_MAX -> xxh3Hash128(buffer, XXH3_STRIPE, buffered, seed, secret, result)
        else -> finishLong { b0, b1, b2, b3, b4, b5, b6, b7 ->
            xxh3Finish128(b0, b1, b2, b3, b4, b5, b6, b7, secret, length, result)
        }
    }

    /**
     * Processes the pending stripes but the last one, without modifying the state,
     * and passes the final accumulators to [result].
     */
    private inline fun <R> finishLong(result: (Long, Long, Long, Long, Long, Long, Long, Long) -> R): R {
        val stripes = (buffered - 1) / XXH3_STRIPE
        return xxh3Stripes(
            a0, a1, a2, a3, a4, a5, a6, a7,
            buffer, XXH3_STRIPE, stripes, stripe, secret,
        ) { b0, b1, b2, b3, b4, b5, b6, b7 ->
            // The last stripe ends at the last pending byte, and may start among the last processed bytes
            xxh3LastStripe(b0, b1, b2, b3, b4, b5, b6, b7, buffer, buffered, secret, result)
        }
    }

    @Suppress("LongParameterList") // The eight accumulators of the specification
    private fun store(b0: Long, b1: Long, b2: Long, b3: Long, b4: Long, b5: Long, b6: Long, b7: Long) {
        a0 = b0
        a1 = b1
        a2 = b2
        a3 = b3
        a4 = b4
        a5 = b5
        a6 = b6
        a7 = b7
    }

    private companion object {
        private const val STRIPES_PER_BLOCK: Int = 4
        private const val CAPACITY: Int = STRIPES_PER_BLOCK * XXH3_STRIPE
    }
}
