package org.danilopianini.noncryptohash.xxhash

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.requireRange

/**
 * XXH128, the 128-bit variant of the third generation of xxHash by Yann Collet, as in its
 * [specification](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md) (`XXH3_128bits_withSeed`).
 * It shares the algorithms and the performance profile of [XxHash3]: see its documentation.
 *
 * The [seed] is read as an unsigned 64-bit integer.
 * [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns the high then the low 64 bits of the hash,
 * both big-endian, as the canonical representation of the specification;
 * [Digest.digestLong][org.danilopianini.noncryptohash.Digest.digestLong] returns the low 64 bits.
 *
 * The one-shot byte array methods hash without allocating.
 *
 * @property seed the seed of the hash.
 */
class XxHash128(val seed: Long = 0) : HashFunction {
    private val longSecret: LongArray = if (seed == 0L) XXH3_DEFAULT_SECRET else xxh3Secret(seed)

    override val bits: Int = BITS

    override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long {
        requireRange(bytes, offset, length)
        return xxh3Hash128(bytes, offset, length, seed, longSecret) { low, _ -> low }
    }

    override fun newDigest(): XxHash3Digest = XxHash3Digest(seed, longSecret, BITS)

    private companion object {
        private const val BITS: Int = 128
    }
}
