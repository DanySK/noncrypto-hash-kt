package org.danilopianini.noncryptohash.siphash

import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.readLongLittleEndian
import org.danilopianini.noncryptohash.common.requireRange

/**
 * SipHash, by Jean-Philippe Aumasson and Daniel J. Bernstein, as in its
 * [specification](https://www.aumasson.jp/siphash/siphash.pdf): either [SipHash24] or [SipHash13].
 *
 * SipHash is a keyed hash (a pseudorandom function) with a 128-bit key: as long as the key is secret,
 * an adversary cannot craft inputs that collide, which protects hash tables from flooding attacks.
 * It is slower than the other hashes of this library, and it is not meant to authenticate messages.
 *
 * The key is ([k0], [k1]): the two halves of the 16-byte key of the specification, read little-endian.
 * [Digest.digest][org.danilopianini.noncryptohash.Digest.digest] returns the 8 bytes of the 64-bit hash big-endian:
 * the reverse of the bytes written by the reference implementation.
 *
 * The one-shot byte array methods hash without allocating a digest.
 *
 * @property k0 the first 8 bytes of the key, little-endian.
 * @property k1 the last 8 bytes of the key, little-endian.
 */
sealed class SipHashFunction(val k0: Long, val k1: Long) : HashFunction {
    /**
     * The number of SipRounds per 8-byte block.
     */
    internal abstract val compressionRounds: Int

    /**
     * The number of SipRounds of the finalization.
     */
    internal abstract val finalizationRounds: Int

    final override val bits: Int = Long.SIZE_BITS

    final override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long {
        requireRange(bytes, offset, length)
        var v0 = k0 xor INIT0
        var v1 = k1 xor INIT1
        var v2 = k0 xor INIT2
        var v3 = k1 xor INIT3
        val end = offset + length
        val blocksEnd = end - (length and BLOCK_MASK)
        for (index in offset until blocksEnd step Long.SIZE_BYTES) {
            val block = readLongLittleEndian(bytes, index)
            sipRounds(compressionRounds, v0, v1, v2, v3 xor block) { a, b, c, d ->
                v0 = a xor block
                v1 = b
                v2 = c
                v3 = d
            }
        }
        var last = lengthBits(length.toLong())
        for (index in end - 1 downTo blocksEnd) {
            last = last or ((bytes[index].toLong() and BYTE_MASK) shl ((index - blocksEnd) * Byte.SIZE_BITS))
        }
        return sipFinish(v0, v1, v2, v3, last, compressionRounds, finalizationRounds)
    }

    final override fun newDigest(): SipHashDigest = SipHashDigest(k0, k1, compressionRounds, finalizationRounds)

    private companion object {
        private const val BLOCK_MASK: Int = 7
        private const val BYTE_MASK: Long = 0xFF
    }
}
