package org.danilopianini.noncryptohash.crc

/**
 * CRC-32 (ISO-HDLC), the checksum of zip, gzip, PNG, and Ethernet,
 * with the IEEE polynomial `0x04c11db7` (`0xedb88320` reflected).
 * It matches `java.util.zip.CRC32` and Guava's `Hashing.crc32()`.
 *
 * See [Crc32Function] for the representation of the CRC.
 */
class Crc32 : Crc32Function() {
    override val table: Crc32Table = TABLE

    private companion object {
        private const val POLYNOMIAL: Int = -0x1247_7ce0 // 0xedb88320
        private val TABLE = Crc32Table(POLYNOMIAL)
    }
}
