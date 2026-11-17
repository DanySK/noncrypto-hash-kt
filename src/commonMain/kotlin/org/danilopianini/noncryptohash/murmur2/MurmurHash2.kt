package org.danilopianini.noncryptohash.murmur2

import org.danilopianini.noncryptohash.Digest
import org.danilopianini.noncryptohash.HashFunction
import org.danilopianini.noncryptohash.common.BufferedDigest
import org.danilopianini.noncryptohash.common.readIntLittleEndian
import org.danilopianini.noncryptohash.common.requireRange

/**
 * MurmurHash2, 32-bit variant (`MurmurHash2` in the reference implementation by Austin Appleby).
 *
 * Prefer [MurmurHash32][org.danilopianini.noncryptohash.murmur3.MurmurHash32] for new uses:
 * MurmurHash2 is here for compatibility, most notably with the default partitioner of Apache Kafka,
 * which hashes keys with [KAFKA_SEED] (its `Utils.murmur2`) and picks the partition
 * `(hash and 0x7fffffff) % partitions`.
 * It also matches `MurmurHash2.hash32` of Apache Commons Codec.
 *
 * MurmurHash2 mixes the length of the input in before reading it,
 * so its digests keep the whole input in memory until they digest it:
 * prefer the one-shot byte array methods, which hash without allocating.
 *
 * [Digest.digestLong] zero-extends the hash, and [Digest.digest] returns its 4 bytes big-endian.
 *
 * @property seed the seed of the hash.
 */
class MurmurHash2(val seed: Int = 0) : HashFunction {
    override val bits: Int = Int.SIZE_BITS

    override fun hashInt(bytes: ByteArray, offset: Int, length: Int): Int {
        requireRange(bytes, offset, length)
        var hash = seed xor length
        val end = offset + length
        val blocksEnd = end - (length and TAIL_MASK)
        for (index in offset until blocksEnd step Int.SIZE_BYTES) {
            var k = readIntLittleEndian(bytes, index) * M
            k = (k xor (k ushr R)) * M
            hash = hash * M xor k
        }
        if (blocksEnd < end) {
            var tail = 0
            for (index in end - 1 downTo blocksEnd) {
                tail = (tail shl Byte.SIZE_BITS) or (bytes[index].toInt() and BYTE_MASK)
            }
            hash = (hash xor tail) * M
        }
        hash = (hash xor (hash ushr FINAL_SHIFT_1)) * M
        return hash xor (hash ushr FINAL_SHIFT_2)
    }

    override fun hashLong(bytes: ByteArray, offset: Int, length: Int): Long =
        hashInt(bytes, offset, length).toLong() and INT_MASK

    override fun newDigest(): Digest = BufferedDigest(this)

    /**
     * Constants of MurmurHash2.
     */
    companion object {
        /**
         * The seed used by Apache Kafka to partition records by key (`0x9747b28c`).
         */
        const val KAFKA_SEED: Int = -0x68b8_4d74
        private const val M: Int = 0x5bd1_e995
        private const val R: Int = 24
        private const val FINAL_SHIFT_1: Int = 13
        private const val FINAL_SHIFT_2: Int = 15
        private const val TAIL_MASK: Int = 3
        private const val BYTE_MASK: Int = 0xFF
        private const val INT_MASK: Long = 0xFFFF_FFFFL
    }
}
