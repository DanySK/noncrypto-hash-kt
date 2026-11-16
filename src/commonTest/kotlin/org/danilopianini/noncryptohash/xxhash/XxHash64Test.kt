package org.danilopianini.noncryptohash.xxhash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.danilopianini.noncryptohash.DigestContract
import org.danilopianini.noncryptohash.testInput
import org.danilopianini.noncryptohash.toHex

/**
 * Reference vectors generated with the reference C implementation (`XXH64` of libxxhash 0.8).
 * Hashes are the hexadecimal digits of the 64-bit value; seeds are read as unsigned.
 */
class XxHash64Test {
    private val byteVectors: List<Vector<Int>> = listOf(
        Vector(0, 0L, "ef46db3751d8e999"),
        Vector(1, 0L, "f592c0c7639c4cb6"),
        Vector(2, 0L, "78f1ae91e3b05e99"),
        Vector(3, 0L, "22c08528601d4f27"),
        Vector(4, 0L, "fb1e5cf2f1ae4d95"),
        Vector(5, 0L, "9d213eca1f68f273"),
        Vector(6, 0L, "0f28996d1449561e"),
        Vector(7, 0L, "5613ac510496c04e"),
        Vector(8, 0L, "57cb2b7521f3e21a"),
        Vector(9, 0L, "c3f1d09775257b66"),
        Vector(10, 0L, "920f407f474903ff"),
        Vector(11, 0L, "1bef4539443a2d5a"),
        Vector(12, 0L, "2f53b00266039e64"),
        Vector(13, 0L, "aed0293a7bb13c7a"),
        Vector(14, 0L, "393648aa0a97d46f"),
        Vector(15, 0L, "90a9714eb00e8d29"),
        Vector(16, 0L, "c6843cef99721174"),
        Vector(17, 0L, "f72e5e622b272ad6"),
        Vector(18, 0L, "ade42c5775a43c96"),
        Vector(19, 0L, "c3bdab4626258cea"),
        Vector(20, 0L, "a62c18328d2d838d"),
        Vector(21, 0L, "2f04ff79d78f8827"),
        Vector(22, 0L, "1e5b0540defc3911"),
        Vector(23, 0L, "5e6a1fe05d7c06f8"),
        Vector(24, 0L, "fa2d58b357e1565e"),
        Vector(25, 0L, "8adefb8c854b47a5"),
        Vector(26, 0L, "2b085f5f9da33210"),
        Vector(27, 0L, "87b80516e95cbbbc"),
        Vector(28, 0L, "ff5c77ef1446f7e5"),
        Vector(29, 0L, "8b15b1001a84dbdb"),
        Vector(30, 0L, "6077f1ac1f080751"),
        Vector(31, 0L, "e4a0e629e519a4ae"),
        Vector(32, 0L, "cc6b8aaada790b2d"),
        Vector(33, 0L, "35ec49850475a832"),
        Vector(34, 0L, "f56a57787fd5fe4e"),
        Vector(35, 0L, "59de01e65b64555b"),
        Vector(36, 0L, "bebb6d8c24fb3cfa"),
        Vector(37, 0L, "5f313a6790502101"),
        Vector(38, 0L, "9ffd421ba9cd1bab"),
        Vector(39, 0L, "22984e41b53c1210"),
        Vector(40, 0L, "3b21ed23eea85c2d"),
        Vector(41, 0L, "25c2b9e2f81a6a9d"),
        Vector(42, 0L, "126f6f74a01c7118"),
        Vector(43, 0L, "03c47edf3964bb63"),
        Vector(44, 0L, "a9a8f93ce6f588d3"),
        Vector(45, 0L, "fc003d355fa58a61"),
        Vector(46, 0L, "2af21f2c679a3b30"),
        Vector(47, 0L, "16fdd9ca22942dda"),
        Vector(48, 0L, "f6c2a2407a06c116"),
        Vector(49, 0L, "1951edf80e0e88a1"),
        Vector(50, 0L, "8966cf42dc674cb9"),
        Vector(51, 0L, "ca011706caf89aa3"),
        Vector(52, 0L, "c97263946e120e53"),
        Vector(53, 0L, "f540a55131f40746"),
        Vector(54, 0L, "ab9a21d36f37bce2"),
        Vector(55, 0L, "66a3eed6214e51ff"),
        Vector(56, 0L, "d44977c91550cf3b"),
        Vector(57, 0L, "52f38f5975796217"),
        Vector(58, 0L, "9996904218108a75"),
        Vector(59, 0L, "d8213a1477e2e240"),
        Vector(60, 0L, "2bafa54dfa33d5a4"),
        Vector(61, 0L, "cdc4536663934e01"),
        Vector(62, 0L, "57b94e18c6b9173f"),
        Vector(63, 0L, "bf9f0ba3cf95b28a"),
        Vector(64, 0L, "155ccce4bf32befc"),
        Vector(65, 0L, "da5ee441a595cfb8"),
        Vector(66, 0L, "4b4fc775ab6cf0fb"),
        Vector(67, 0L, "5e65106afea9135e"),
        Vector(68, 0L, "775582f16a463143"),
        Vector(69, 0L, "122f5c97b04ed270"),
        Vector(70, 0L, "0d74d36bafb8d9c7"),
        Vector(71, 0L, "81e0a52b9c0e1651"),
        Vector(72, 0L, "657fc372b173aae2"),
        Vector(0, 42L, "98b1582b0977e704"),
        Vector(1, 42L, "0ed0d6a13cc52e0a"),
        Vector(2, 42L, "054cd9899094cf8f"),
        Vector(3, 42L, "1d78b776eafa43d8"),
        Vector(4, 42L, "25ad71c276a88f81"),
        Vector(5, 42L, "dcd9883a8c894cc0"),
        Vector(6, 42L, "92e06afba65ab962"),
        Vector(7, 42L, "23cef44b0ba08fbc"),
        Vector(8, 42L, "48f76c205ce221a1"),
        Vector(9, 42L, "55b4abc5c2b49ddd"),
        Vector(10, 42L, "f93480bb03076530"),
        Vector(11, 42L, "39ec4fd892a8cf2e"),
        Vector(12, 42L, "a12d5dcdb37a0d4d"),
        Vector(13, 42L, "164a8fff156b1435"),
        Vector(14, 42L, "49230c5b0cdb7826"),
        Vector(15, 42L, "fc984faf1ae788b1"),
        Vector(16, 42L, "9cf687a398b1d145"),
        Vector(17, 42L, "46a5e039a6f8fd87"),
        Vector(18, 42L, "ea0ccdeaf0517c41"),
        Vector(19, 42L, "e1f77d10e4e7b2e9"),
        Vector(20, 42L, "ec8ab7ab1db845ec"),
        Vector(21, 42L, "2a36bc0faeaff689"),
        Vector(22, 42L, "46f01664f4e1857d"),
        Vector(23, 42L, "3997f3fde040b72b"),
        Vector(24, 42L, "f8bd9813fd31a206"),
        Vector(25, 42L, "a55c7486ada63a2f"),
        Vector(26, 42L, "07ce2545f7bdf5e6"),
        Vector(27, 42L, "d2012309ceacdfcf"),
        Vector(28, 42L, "46219a9acc2f5c02"),
        Vector(29, 42L, "9901b4e029b79d36"),
        Vector(30, 42L, "667a480fac2bbdfa"),
        Vector(31, 42L, "b5ff3fef27553617"),
        Vector(32, 42L, "397cf7d12b7e438c"),
        Vector(33, 42L, "e39469f42e2fd6e4"),
        Vector(34, 42L, "60a155e527670a07"),
        Vector(35, 42L, "53b3bbc8cd79e906"),
        Vector(36, 42L, "0b7f9c13a5b33501"),
        Vector(37, 42L, "d9c3149a34c3576c"),
        Vector(38, 42L, "c30166a68f752e8a"),
        Vector(39, 42L, "9532d21e0bb9bb51"),
        Vector(40, 42L, "b0c82a4cd7b5bb7b"),
        Vector(41, 42L, "2ffd3cb279152a48"),
        Vector(42, 42L, "175f2a5403f19c79"),
        Vector(43, 42L, "b877d7c570ead8dc"),
        Vector(44, 42L, "d30a0107cc47c821"),
        Vector(45, 42L, "337d5c3ae602a491"),
        Vector(46, 42L, "a7231ecc96160bce"),
        Vector(47, 42L, "98726cbea1005c0c"),
        Vector(48, 42L, "86172441a17ec30d"),
        Vector(49, 42L, "eb8e6714c68d170c"),
        Vector(50, 42L, "d99bb58d2391772a"),
        Vector(51, 42L, "3a4f7f0c20398e0b"),
        Vector(52, 42L, "2a5c3f5993f7fd0f"),
        Vector(53, 42L, "81536cdaee4a963e"),
        Vector(54, 42L, "8748af330d364f4f"),
        Vector(55, 42L, "ab5791ca3f232668"),
        Vector(56, 42L, "ee98b0811dadbe38"),
        Vector(57, 42L, "312c9ffa2cea0bc8"),
        Vector(58, 42L, "24568d77540fe3d6"),
        Vector(59, 42L, "ec674a380b9d73ba"),
        Vector(60, 42L, "6a9bbbbb5d83f093"),
        Vector(61, 42L, "0f8f4c94c2c94b47"),
        Vector(62, 42L, "67febc1371ded1ad"),
        Vector(63, 42L, "d61515af63d708d1"),
        Vector(64, 42L, "d86cde23b501d126"),
        Vector(65, 42L, "9b35746e7fda8246"),
        Vector(66, 42L, "6157b5a0a8f3178a"),
        Vector(67, 42L, "12c0e11930ecd109"),
        Vector(68, 42L, "5083c4aacf05e4fe"),
        Vector(69, 42L, "e08e7582ed781af5"),
        Vector(70, 42L, "3b926e7cc679aec9"),
        Vector(71, 42L, "1e13e2dbc02b3dab"),
        Vector(72, 42L, "e015d808585853e5"),
        Vector(0, -7046029288634856825L, "6ec6d05f61c7e7a7"),
        Vector(1, -7046029288634856825L, "11c15bc64227a259"),
        Vector(2, -7046029288634856825L, "a122d2139bc24960"),
        Vector(3, -7046029288634856825L, "680fb1b072b12822"),
        Vector(4, -7046029288634856825L, "1a24432ce8cca8ab"),
        Vector(5, -7046029288634856825L, "8467ad836f6ae823"),
        Vector(6, -7046029288634856825L, "307b135f477b7125"),
        Vector(7, -7046029288634856825L, "eb83e677abc7457f"),
        Vector(8, -7046029288634856825L, "0eacb01d241d894d"),
        Vector(9, -7046029288634856825L, "9b98a7a55393f326"),
        Vector(10, -7046029288634856825L, "e582ac37b7e08865"),
        Vector(11, -7046029288634856825L, "56f879f543698388"),
        Vector(12, -7046029288634856825L, "86896eb474efe613"),
        Vector(13, -7046029288634856825L, "5bcbd57d980f93bf"),
        Vector(14, -7046029288634856825L, "146531a2f056d659"),
        Vector(15, -7046029288634856825L, "6e0609ff46df0f7e"),
        Vector(16, -7046029288634856825L, "23a8cf6ad53b5290"),
        Vector(17, -7046029288634856825L, "ff1e142c03497138"),
        Vector(18, -7046029288634856825L, "1576848ed729f697"),
        Vector(19, -7046029288634856825L, "fba91f028d31b50b"),
        Vector(20, -7046029288634856825L, "3e0348e8ac13d4a7"),
        Vector(21, -7046029288634856825L, "410f06095517f18b"),
        Vector(22, -7046029288634856825L, "76801055131ac262"),
        Vector(23, -7046029288634856825L, "22c9f91b609fafe4"),
        Vector(24, -7046029288634856825L, "51789b8b6d9168f8"),
        Vector(25, -7046029288634856825L, "ef03d485d794f00b"),
        Vector(26, -7046029288634856825L, "a3b72f65eb4385e2"),
        Vector(27, -7046029288634856825L, "888a91077cc555bb"),
        Vector(28, -7046029288634856825L, "c73227e9dcb89543"),
        Vector(29, -7046029288634856825L, "90f289f011212c13"),
        Vector(30, -7046029288634856825L, "08981809e9cef330"),
        Vector(31, -7046029288634856825L, "5c59f004b6611b70"),
        Vector(32, -7046029288634856825L, "7b07232241d2ce0c"),
        Vector(33, -7046029288634856825L, "7b94d2f19b051eff"),
        Vector(34, -7046029288634856825L, "9f5a327536394b41"),
        Vector(35, -7046029288634856825L, "d48fe18fbacf24a3"),
        Vector(36, -7046029288634856825L, "bc7277b08a9b81af"),
        Vector(37, -7046029288634856825L, "42ebe4d04062f281"),
        Vector(38, -7046029288634856825L, "eafadf0f32351b3c"),
        Vector(39, -7046029288634856825L, "5662895146d690d4"),
        Vector(40, -7046029288634856825L, "4c301798e7aba5eb"),
        Vector(41, -7046029288634856825L, "b9fe2cf2da8fe2d7"),
        Vector(42, -7046029288634856825L, "ae4b06541bf1884e"),
        Vector(43, -7046029288634856825L, "104cc759d426a950"),
        Vector(44, -7046029288634856825L, "6861937d6ae0b35d"),
        Vector(45, -7046029288634856825L, "7c31197fecfe91bb"),
        Vector(46, -7046029288634856825L, "01162cf0da017d6c"),
        Vector(47, -7046029288634856825L, "aa70e4fd55793f74"),
        Vector(48, -7046029288634856825L, "8c427fb07c684e53"),
        Vector(49, -7046029288634856825L, "2b183862b26fdb5d"),
        Vector(50, -7046029288634856825L, "4c55856070887878"),
        Vector(51, -7046029288634856825L, "5f0e1c63363ece4e"),
        Vector(52, -7046029288634856825L, "33a5b00d5cbe3193"),
        Vector(53, -7046029288634856825L, "b4772b7542efeae0"),
        Vector(54, -7046029288634856825L, "e32489c2bfe63a2f"),
        Vector(55, -7046029288634856825L, "d3e15c6160a63f1f"),
        Vector(56, -7046029288634856825L, "8bd1c6e17934c2dc"),
        Vector(57, -7046029288634856825L, "7821a5d062c3a53e"),
        Vector(58, -7046029288634856825L, "5b398c69fb6ef9f4"),
        Vector(59, -7046029288634856825L, "ea392e15f557bf7b"),
        Vector(60, -7046029288634856825L, "1204825027ea91de"),
        Vector(61, -7046029288634856825L, "97e9dd38bf6f005e"),
        Vector(62, -7046029288634856825L, "b8a77695b698e216"),
        Vector(63, -7046029288634856825L, "a4bdf9e7d15f7ed0"),
        Vector(64, -7046029288634856825L, "d10dfae7e9e3edec"),
        Vector(65, -7046029288634856825L, "f9a52a50c1b7ebf1"),
        Vector(66, -7046029288634856825L, "f78bbe3401e115aa"),
        Vector(67, -7046029288634856825L, "11ff0cf93ac57ecc"),
        Vector(68, -7046029288634856825L, "eb40240027a205db"),
        Vector(69, -7046029288634856825L, "74adb0f2c32ad6da"),
        Vector(70, -7046029288634856825L, "0c2cac022d23097b"),
        Vector(71, -7046029288634856825L, "45f096d3d47c168c"),
        Vector(72, -7046029288634856825L, "084f19b7e31b5a55"),
    )

    private val textVectors: List<Vector<String>> = listOf(
        Vector("", 0L, "ef46db3751d8e999"),
        Vector("a", 0L, "d24ec4f1a98c6e5b"),
        Vector("abc", 0L, "44bc2cf5ad770999"),
        Vector("hello", 0L, "26c7827d889f6da3"),
        Vector("The quick brown fox jumps over the lazy dog", 0L, "0b242d361fda71bc"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 0L, "d6909d270bcf6aff"),
        Vector("", 1L, "d5afba1336a3be4b"),
        Vector("a", 1L, "dec2bc81c3cd46c6"),
        Vector("abc", 1L, "bea9ca8199328908"),
        Vector("hello", 1L, "23dd71cb04d0a1b2"),
        Vector("The quick brown fox jumps over the lazy dog", 1L, "df5091b6dad2c6db"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 1L, "7e408a8364fd7758"),
        Vector("", 42L, "98b1582b0977e704"),
        Vector("a", 42L, "88e4fe59adf7b0cc"),
        Vector("abc", 42L, "13c1d910702770e6"),
        Vector("hello", 42L, "c3629e6318d53932"),
        Vector("The quick brown fox jumps over the lazy dog", 42L, "aa9f288a8baa3d3f"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 42L, "3a637af2184d8f8f"),
        Vector("", -1L, "298f4c84b24f5380"),
        Vector("a", -1L, "60c43759873ece62"),
        Vector("abc", -1L, "28306e589cc02176"),
        Vector("hello", -1L, "01bf361df0d21898"),
        Vector("The quick brown fox jumps over the lazy dog", -1L, "9f3d039cd26eeafc"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", -1L, "476938f3fa104006"),
        Vector("", 9223372036854775807L, "0ba820990ebb95e3"),
        Vector("a", 9223372036854775807L, "c6570aed7dd77629"),
        Vector("abc", 9223372036854775807L, "a1059eaf8c24bb4d"),
        Vector("hello", 9223372036854775807L, "59d77118f5239a7c"),
        Vector("The quick brown fox jumps over the lazy dog", 9223372036854775807L, "bce975908f12032a"),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 9223372036854775807L, "92f5b43453e80bec"),
    )

    @Test
    fun `byte arrays match the reference vectors in one shot`() {
        byteVectors.forEach { (size, seed, hex) ->
            val input = testInput(size)
            assertEquals(hex.toULong(16).toLong(), XxHash64(seed).hashLong(input), "size $size, seed $seed")
            assertEquals(hex.toULong(16).toInt(), XxHash64(seed).hashInt(input), "size $size, seed $seed")
            assertEquals(hex, XxHash64(seed).newDigest().update(input).digest().toHex(), "size $size, seed $seed")
        }
    }

    @Test
    fun `byte arrays match the reference vectors in any chunking`() {
        byteVectors.forEach { (size, seed, hex) ->
            DigestContract {
                XxHash64Digest(seed)
            }.assertChunkingDoesNotMatter(testInput(size), hex, "size $size, seed $seed")
        }
    }

    @Test
    fun `the digest honors the shared contract`() {
        listOf(0L, 7L, -1L).forEach { seed -> DigestContract { XxHash64Digest(seed) }.assertAll() }
    }

    @Test
    fun `one shot hashing honors the offset and length`() {
        val input = testInput(80)
        listOf(0 to 80, 3 to 0, 5 to 3, 7 to 32, 1 to 77, 9 to 45).forEach { (offset, length) ->
            assertEquals(
                XxHash64(42).hashLong(input.copyOfRange(offset, offset + length)),
                XxHash64(42).hashLong(input, offset, length),
                "offset $offset, length $length",
            )
        }
        assertFailsWith<IllegalArgumentException> { XxHash64().hashLong(input, 70, 11) }
    }

    @Test
    fun `text matches the reference vectors of its UTF-8 encoding`() {
        textVectors.forEach { (text, seed, hex) ->
            assertEquals(hex.toULong(16).toLong(), XxHash64(seed).hashLong(text), "'$text', seed $seed")
            assertEquals(hex, XxHash64(seed).newDigest().update(text).digest().toHex(), "'$text', seed $seed")
        }
    }

    @Test
    fun `the digest has 64 bits`() {
        assertEquals(64, XxHash64().bits)
        assertEquals(8, XxHash64Digest().digest().size)
    }

    private data class Vector<T>(val input: T, val seed: Long, val hex: String)
}
