package org.danilopianini.noncryptohash.crc

/**
 * CRC-32C (Castagnoli), the checksum of iSCSI, SCTP, ext4, and Kafka record batches,
 * with the Castagnoli polynomial `0x1edc6f41` (`0x82f63b78` reflected).
 * It matches `java.util.zip.CRC32C` and Guava's `Hashing.crc32c()`.
 *
 * See [Crc32Function] for the representation of the CRC.
 */
class Crc32c : Crc32Function() {
    override val table: Crc32Table = TABLE

    private companion object {
        private const val POLYNOMIAL: Int = -0x7d09_c488 // 0x82f63b78
        private val TABLE = Crc32Table(POLYNOMIAL)
    }
}
