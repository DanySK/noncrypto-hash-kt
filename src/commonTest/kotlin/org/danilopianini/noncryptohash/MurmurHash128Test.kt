package org.danilopianini.noncryptohash

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Reference vectors generated with Guava's `Hashing.murmur3_128` (non-negative seeds)
 * and with the reference C implementation (negative seeds, which Guava sign-extends).
 * Hashes are the hexadecimal digits of the 128-bit value `h2 << 64 | h1`; the long is `h1`.
 */
class MurmurHash128Test {
    private val byteVectors: List<Vector<Int>> = listOf(
        Vector(0, 0, "00000000000000000000000000000000", 0L),
        Vector(1, 0, "7a434b816c4508dc932fc7cce617f1e7", -7840828743381159449L),
        Vector(2, 0, "8549c3b277c47536cff7e5ae5471b39d", -3461045251707128931L),
        Vector(3, 0, "0cdcf4fb816ab2436afac0b8de81a4b1", 7708685612437578929L),
        Vector(4, 0, "8f4cf22ad9a420cdd3a4eed1b81f9f72", -3196167251021553806L),
        Vector(5, 0, "ad93f9759963f50bb0330f40087f990b", -5750235531527087861L),
        Vector(6, 0, "4b5791ad3829937e32d1f10b04077a12", 3661973001643457042L),
        Vector(7, 0, "a08f38dfaa7ff6f98340cc686662983b", -8988960107465107397L),
        Vector(8, 0, "d02221832d7af9a1f0b144007f89ced7", -1103025664798634281L),
        Vector(9, 0, "cbde24182efe09a9dbb3088eaec8a0b1", -2615737549661364047L),
        Vector(10, 0, "7a1ac716596298b07fc82ef8fd4f371e", 9207661085095573278L),
        Vector(11, 0, "c5c7129b727fc1d6ce105a4d0920d564", -3598276815356897948L),
        Vector(12, 0, "de304d589b0ddbf811eea59fafc3bbb8", 1292152248369134520L),
        Vector(13, 0, "f34ba40d12f9b27e3c0bc0c7790cc4e7", 4326763829981398247L),
        Vector(14, 0, "27302e3cea75fb094af05278beeea171", 5399906631770087793L),
        Vector(15, 0, "49ca338fe7701fac2906f047b67f83ff", 2956314396210463743L),
        Vector(16, 0, "885aae87bb6c5ff7da9c66580c5ef0fb", -2694165948723695365L),
        Vector(17, 0, "e36790301698fce078b8ee9a775e07d1", 8698965027461138385L),
        Vector(18, 0, "16d1b21eec8d67ac5022ece9b605f7d8", 5774438160767776728L),
        Vector(19, 0, "3d2b31d643027caf40591a6345e2fd5e", 4636766305031224670L),
        Vector(20, 0, "a65eec4ab46824eef85aeb21888559f3", -550869475142575629L),
        Vector(21, 0, "93818c98df190fa82c128c13418db6f3", 3175754701581694707L),
        Vector(22, 0, "6dfadfaec1dcf534c0ffc3389f035072", -4539695251412791182L),
        Vector(23, 0, "5ad5c324b9edfa9901b7d4fb84dc53aa", 123801691506889642L),
        Vector(24, 0, "e8f405aaf3f01b038372e2feeb61eb1c", -8974861522897343716L),
        Vector(25, 0, "704bb843bd5ff913ed9e2943729d5da2", -1324575870737883742L),
        Vector(26, 0, "628fa90e86818db59fcd422e337cdec4", -6931811485253574972L),
        Vector(27, 0, "e3a5ff0398ea8b76454a6a1202a0fd74", 4992919762479676788L),
        Vector(28, 0, "82b2e058cfa3ecdac2ea419f1d4c02de", -4401633534154112290L),
        Vector(29, 0, "bef6e3ba00dbfc062ab2e5425a3cf241", 3076773568592015937L),
        Vector(30, 0, "3e2a6a483ba0dd7cfde530955c73468b", -151661594387724661L),
        Vector(31, 0, "cb6926489e7b3763b1ca061ed4c5532f", -5635685254212267217L),
        Vector(32, 0, "3a5200924dcdd6ffaf7374eb8efe799b", -5804166939685258853L),
        Vector(33, 0, "15c06fbdb5df8af908b88a88c3099ba9", 628404468010556329L),
        Vector(34, 0, "c970e3964acebd9446e6fbb70374f1b8", 5109047590753989048L),
        Vector(35, 0, "a38faf048c7c13063db6d4b9af498f9f", 4446975576049815455L),
        Vector(36, 0, "1c67089590905310aee3ca841fccf7f7", -5844605222578751497L),
        Vector(37, 0, "4b78961252ae7b6cff4d3072c71df4b3", -50330751306173261L),
        Vector(38, 0, "437d03b403801e495003e0c3f8da178f", 5765699080262653839L),
        Vector(39, 0, "836db813dc4ac3f8244221d812da51c7", 2612687945741259207L),
        Vector(40, 0, "15f2951b4c05748bbf77aa22e65e7cfc", -4650061023366185732L),
        Vector(0, 42, "d1016610da11cbb9f02aa77dfa1b8523", -1140915396076141277L),
        Vector(1, 42, "b9f37a295a460be81495b72690ad6b49", 1483293028552371017L),
        Vector(2, 42, "395cfbb3ae9b04be22f631fa60c22608", 2519255992995292680L),
        Vector(3, 42, "ab180ac3f390b911b4eb76eae8abab80", -5410099776057529472L),
        Vector(4, 42, "429771fbe5be4ac519f4b7e99d91b549", 1870321959264433481L),
        Vector(5, 42, "b991ac5fcab71c8178d77c76b40ee0fc", 8707565253813002492L),
        Vector(6, 42, "548757bc8f012656cfa7affa1efd7ba5", -3483622297951175771L),
        Vector(7, 42, "3462c34727c5759fc1a4b41f44ebdb31", -4493268481815618767L),
        Vector(8, 42, "cdf4a727435b63a7b3381f253f1f2b67", -5532637897391395993L),
        Vector(9, 42, "51bb1137ee50f5f32b9d4be3cfbdcc3f", 3142751556789455935L),
        Vector(10, 42, "74ff26593bcc8be78561a9b67b54029c", -8835594392705957220L),
        Vector(11, 42, "d26b752a9db04138ba7f85952273472a", -5008137385038100694L),
        Vector(12, 42, "ce1dd0ceb2cfc413866ef056ae2620ad", -8759799970109448019L),
        Vector(13, 42, "231d088df0f9941f5743a54b88d07266", 6288051248575836774L),
        Vector(14, 42, "decc57ba967958a868c53df623f889ec", 7549508477731244524L),
        Vector(15, 42, "6ed32837b07a729a13ec2b575f368709", 1435570035483903753L),
        Vector(16, 42, "a351713a540fc47b0db7e57d84e9115e", 988510970494652766L),
        Vector(17, 42, "e896d0c8eebdd7646753dd78b706ca59", 7445538119510051417L),
        Vector(18, 42, "6a7af0ccc80c646cdf05643aecea4efa", -2376383024122409222L),
        Vector(19, 42, "ba49c5a903c765a7bb3024b1cb43e62e", -4958422843696880082L),
        Vector(20, 42, "71192cabac28b75f0d53be10d250a7f8", 960320125017303032L),
        Vector(21, 42, "3cdc63217b12ff0e4575c97d55d93e33", 5005128101040569907L),
        Vector(22, 42, "911f3fb2a0f2976b3b714647e699f822", 4283281995231524898L),
        Vector(23, 42, "a9c1e29c0517ddc1c5ee6f09416c6ce1", -4184284918237598495L),
        Vector(24, 42, "5442314f081efe0e0a866149d2508204", 758400556947505668L),
        Vector(25, 42, "8f66bfd548a4235445f006b258382270", 5039535346081604208L),
        Vector(26, 42, "48861faefde164ff1f2ef47649081f95", 2247002052973043605L),
        Vector(27, 42, "87bcea3e5deaade74a20fff3b1be52c3", 5341550580185584323L),
        Vector(28, 42, "35ae93fe69e3756df9ba5bd63ea114d6", -451947836865440554L),
        Vector(29, 42, "6a75655475e49b888509edddd0cc291b", -8860289254928144101L),
        Vector(30, 42, "4b3b798fc446a98ee9e80e350be450e5", -1592006847279902491L),
        Vector(31, 42, "d4b0319632b43b9e4b6b129b8686ccd5", 5434457834538847445L),
        Vector(32, 42, "8b220a58f37c28c2cdae700c6caa0324", -3625837451321670876L),
        Vector(33, 42, "a370e05ed1e5b6e51bb4cea7ea9f8f2c", 1996447755423158060L),
        Vector(34, 42, "fad0242df8f9e9508ca7658b199e6cfd", -8311562939184288515L),
        Vector(35, 42, "b2de91bd6ab59f9f38919621908dd2c6", 4076204208650310342L),
        Vector(36, 42, "9e0eb94af23d31086106d6057cb15fb0", 6991510790594453424L),
        Vector(37, 42, "39593716fc0aeb041997fc8acbb5e3bc", 1844220245484889020L),
        Vector(38, 42, "926e53038d00e33af11f305524b78954", -1072085044044527276L),
        Vector(39, 42, "c6b6279bf58b889e19a9e9e2c00c04ee", 1849266282106193134L),
        Vector(40, 42, "73768e93a3bf1e3c1e0a94ce7d6f094d", 2164706185493547341L),
    )

    private val textVectors: List<Vector<String>> = listOf(
        Vector("", 0, "00000000000000000000000000000000", 0L),
        Vector("a", 0, "e6b53a48510e895a85555565f6597889", -8839064797231613815L),
        Vector("abc", 0, "3ba2744126ca2d52b4963f3f3fad7867", -5434086359492102041L),
        Vector("hello", 0, "5b1e906a48ae1d19cbd8a7b341bd9b02", -3758069500696749310L),
        Vector(
            "The quick brown fox jumps over the lazy dog",
            0,
            "7a433ca9c49a9347e34bbc7bbc071b6c",
            -2068352364225029268L,
        ),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 0, "c317bfa1d56daddc093bf36ba7dc2e2d", 665393013670555181L),
        Vector("", 1, "51622daa78f835834610abe56eff5cb5", 5048724184180415669L),
        Vector("a", 1, "6be0518ad2ed372847eae1073748cf70", 5182201742351716208L),
        Vector("abc", 1, "ca12c88bf31b256c9c88be4e9a8a61f0", -7167269562150657552L),
        Vector("hello", 1, "128900ef20900135a78ddff5adae8d10", -6373191651385504496L),
        Vector(
            "The quick brown fox jumps over the lazy dog",
            1,
            "625a21a4c967fa20e533566dbbd1e13e",
            -1931104785909292738L,
        ),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 1, "49c3d3877202068e9f02c775e276fe65", -6988804362601038235L),
        Vector("", 42, "d1016610da11cbb9f02aa77dfa1b8523", -1140915396076141277L),
        Vector("a", 42, "25ebca9125f82b1528259ca4fdf626b0", 2892890568104748720L),
        Vector("abc", 42, "7510712b42353d300d85089fb3cff7d6", 974194376405153750L),
        Vector("hello", 42, "2334b875b0efbc7ac4b8b3c960af6f08", -4271466569069007096L),
        Vector(
            "The quick brown fox jumps over the lazy dog",
            42,
            "c4546cf4ec705c8f740dcf93fe0bd5d7",
            8362568317626209751L,
        ),
        Vector("\u65E5\u672C\u8A9E \uD83D\uDE00", 42, "7cb16709ef09a105dedb1b04adff8e4f", -2388285470476890545L),
        Vector("", 2147483647, "c34c2ca1ed468e40656ac7570e166c3f", 7307872522074483775L),
        Vector("a", 2147483647, "2009927be8341a64c11776a6efca8a34", -4533024040565437900L),
        Vector("abc", 2147483647, "1b9ba5f4aa960847ba02c565ebbaf777", -5043251591164266633L),
        Vector("hello", 2147483647, "ff0e4f8c71bd56fe47627b50353885e5", 5143809308831024613L),
        Vector(
            "The quick brown fox jumps over the lazy dog",
            2147483647,
            "63565edf6aa6ebd688b47ff85f570429",
            -8596105084015279063L,
        ),
        Vector(
            "\u65E5\u672C\u8A9E \uD83D\uDE00",
            2147483647,
            "ed72f5f9f988a3cc965d6bfaea615a1d",
            -7611809069768025571L,
        ),
        Vector("abc", -1, "5bf10e33d36c37895a2d798580260f18", 6497983451653082904L),
        Vector(
            "The quick brown fox jumps over the lazy dog",
            -1,
            "647d67096440b412691c1d73a800a18a",
            7573961055907389834L,
        ),
        Vector("abc", -123456789, "7a3eaf468e85cb61b06bc86ad0392327", -5734269339440700633L),
        Vector(
            "The quick brown fox jumps over the lazy dog",
            -123456789,
            "4ed29ef3cd517a385e05179b8f8c8363",
            6774847171344499555L,
        ),
    )

    @Test
    fun `byte arrays match the reference vectors in one shot`() {
        byteVectors.forEach { (size, seed, hex, low) ->
            val input = input(size)
            assertEquals(low, MurmurHash128(seed).hashLong(input), "size $size, seed $seed")
            assertEquals(hex, MurmurHash128(seed).newDigest().update(input).digest().toHex(), "size $size, seed $seed")
        }
    }

    @Test
    fun `byte arrays match the reference vectors in any chunking`() {
        byteVectors.forEach { (size, seed, hex, _) ->
            val input = input(size)
            listOf(1, 3, 7, 8, 15, 16, 17).forEach { chunk ->
                val digest = MurmurHash128Digest(seed)
                input.indices.step(chunk).forEach { start -> digest.update(input, start, minOf(chunk, size - start)) }
                assertEquals(hex, digest.digest().toHex(), "size $size, seed $seed, chunk $chunk")
            }
        }
    }

    @Test
    fun `digesting does not alter the state`() {
        val digest = MurmurHash128Digest().update(input(20))
        val first = digest.digest()
        digest.digestLong()
        assertContentEquals(first, digest.digest())
        digest.update(input(5))
        assertContentEquals(MurmurHash128Digest().update(input(20)).update(input(5)).digest(), digest.digest())
    }

    @Test
    fun `digest into honors the offset and rejects short destinations`() {
        val digest = MurmurHash128Digest().update("abc")
        val destination = ByteArray(20)
        digest.digestInto(destination, 3)
        assertContentEquals(digest.digest(), destination.copyOfRange(3, 19))
        assertFailsWith<IllegalArgumentException> { digest.digestInto(ByteArray(16), 1) }
    }

    @Test
    fun `fixed width updates match their little-endian bytes at every alignment`() {
        (0 until 16).forEach { prefix ->
            val values = listOf(0x0123_4567_89AB_CDEFL, -1L, 0x8000_0000_0000_0001UL.toLong())
            values.forEach { value ->
                val expected = MurmurHash128Digest(7).update(input(prefix))
                val actual = MurmurHash128Digest(7).update(input(prefix))
                expected.update(ByteArray(Long.SIZE_BYTES) { (value ushr (it * Byte.SIZE_BITS)).toByte() })
                    .update(ByteArray(Int.SIZE_BYTES) { (value ushr (it * Byte.SIZE_BITS)).toByte() })
                    .update(ByteArray(Short.SIZE_BYTES) { (value ushr (it * Byte.SIZE_BITS)).toByte() })
                    .update(byteArrayOf(value.toByte()))
                actual.update(value).update(value.toInt()).update(value.toShort()).update(value.toByte())
                assertEquals(expected.digest().toHex(), actual.digest().toHex(), "prefix $prefix, value $value")
            }
        }
    }

    @Test
    fun `negative seeds are zero-extended`() {
        assertEquals(
            MurmurHash128(-1).hashLong("abc"),
            textVectors.single { it.input == "abc" && it.seed == -1 }.low,
        )
    }

    @Test
    fun `resetting restores the seeded initial state`() {
        val digest = MurmurHash128Digest(42).update(input(33))
        digest.reset()
        assertContentEquals(MurmurHash128Digest(42).update("abc").digest(), digest.update("abc").digest())
    }

    @Test
    fun `text matches the reference vectors of its UTF-8 encoding`() {
        textVectors.forEach { (text, seed, hex, low) ->
            assertEquals(low, MurmurHash128(seed).hashLong(text), "'$text', seed $seed")
            assertEquals(hex, MurmurHash128(seed).newDigest().update(text).digest().toHex(), "'$text', seed $seed")
        }
    }

    @Test
    fun `the digest has 128 bits`() {
        assertEquals(128, MurmurHash128().bits)
        assertEquals(16, MurmurHash128Digest().digest().size)
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun input(size: Int): ByteArray = ByteArray(size) { (it * 37 + 11).toByte() }

    private data class Vector<T>(val input: T, val seed: Int, val hex: String, val low: Long)
}
