package org.danilopianini.noncryptohash.xxhash

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.requireRange

/**
 * XXH3, the 64-bit variant of the third generation of xxHash by Yann Collet, as in its
 * [specification](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md) (`XXH3_64bits_withSeed`).
 *
 * XXH3 has dedicated algorithms for inputs of up to 16, 128, and 240 bytes, which make it very fast on short keys,
 * and a vectorizable loop for longer inputs.
 * It relies on 64-bit arithmetic and on 128-bit products, built from 32-bit ones in common Kotlin:
 * on targets where 64-bit integers are emulated, such as JavaScript, prefer
 * [XxHash32] or [MurmurHash32][org.danilopianini.noncryptohash.murmur3.MurmurHash32].
 *
 * The [seed] is read as an unsigned 64-bit integer: a non-zero seed derives a 192-byte secret for long inputs,
 * computed once per instance.
 * [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns the 8 bytes of the hash big-endian,
 * as the canonical representation of the specification.
 *
 * The one-shot byte array methods hash without allocating.
 * Digests buffer up to 256 bytes, since XXH3 needs the whole input of short inputs, and the last 64 bytes of long ones.
 *
 * @property seed the seed of the hash.
 */
class XxHash3(val seed: Long = 0) : HashFunction {
    private val longSecret: LongArray = if (seed == 0L) XXH3_DEFAULT_SECRET else xxh3Secret(seed)

    override val bits: Int = Long.SIZE_BITS

    override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long {
        requireRange(bytes, offset, length)
        return xxh3Hash64(bytes, offset, length, seed, longSecret)
    }

    override fun newDigest(): XxHash3Digest = XxHash3Digest(seed, longSecret, Long.SIZE_BITS)
}
