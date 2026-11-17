# noncrypto-hash-kt

Non-cryptographic hash functions for Kotlin Multiplatform, written in pure common Kotlin.

The library has three priorities, in this order:
1. **Portability**: every algorithm runs on every Kotlin target, and produces the same hash on all of them.
2. **Speed**: no allocations on hot paths, and one-shot methods that skip the streaming machinery.
3. **Memory footprint**: digests keep their pending input in a few fields, without buffers.

These hashes are meant for hash tables, caches, deduplication, sharding, and checksums.
They are **not** cryptographic: never use them where an adversary may choose the input to cause collisions,
or to protect secrets.

**[Benchmarks](https://danysk.github.io/noncrypto-hash-kt/)**: speed and memory of every algorithm on every target,
with the machine each run was executed on.

## Algorithms

| Algorithm | Class | Bits | Notes |
|---|---|---|---|
| CRC-32 | `crc.Crc32` | 32 | Checksum of zip, gzip, and PNG; matches `java.util.zip.CRC32` |
| CRC-32C | `crc.Crc32c` | 32 | Checksum of iSCSI, ext4, and Kafka; matches `java.util.zip.CRC32C` |
| FNV-1a, 32-bit | `fnv.Fnv1a32` | 32 | No seed; fastest for keys of a few bytes, slow on long inputs |
| FNV-1a, 64-bit | `fnv.Fnv1a64` | 64 | No seed; fastest for keys of a few bytes, slow on long inputs |
| MurmurHash2, 32-bit | `murmur2.MurmurHash2` | 32 | For compatibility, e.g., with Kafka's partitioner (`KAFKA_SEED`); digests buffer the whole input |
| MurmurHash3, x64 128-bit | `murmur3.MurmurHash128` | 128 | Matches the reference implementation, and Guava's `murmur3_128` for non-negative seeds |
| MurmurHash3, x86 32-bit | `murmur3.MurmurHash32` | 32 | 32-bit arithmetic only; matches Guava's `murmur3_32_fixed` |
| SipHash-1-3 | `siphash.SipHash13` | 64 | Keyed, resists hash flooding; as in the hash tables of Rust and Python |
| SipHash-2-4 | `siphash.SipHash24` | 64 | Keyed, resists hash flooding; matches Guava's `sipHash24` |
| xxHash, 32-bit (XXH32) | `xxhash.XxHash32` | 32 | 32-bit arithmetic only, so the fastest choice on JavaScript |
| xxHash, 64-bit (XXH64) | `xxhash.XxHash64` | 64 | Fast on 64-bit targets |
| xxHash3, 64-bit (XXH3) | `xxhash.XxHash3` | 64 | Fastest on short keys on 64-bit targets; digests buffer up to 256 bytes |
| xxHash3, 128-bit (XXH128) | `xxhash.XxHash128` | 128 | As XXH3, with a 128-bit hash |

All classes are in the `org.danilopianini.noncryptohash` package, and are validated against the test vectors
of their reference implementation.

## Supported targets

JVM (Java 8 or newer), JavaScript (browser and Node.js), Wasm (JS and WASI), and Kotlin/Native:
Linux, Windows, macOS, iOS, tvOS, watchOS, and Android Native.

## Usage

The library is not released yet. Releases will be published on Maven Central as
`org.danilopianini:noncrypto-hash-kt`.

### One-shot hashing

A `HashFunction` is stateless, configured once (e.g., with a seed), and safe to share across threads:

```kotlin
val murmur = MurmurHash128(seed = 42)
val fromText: Long = murmur.hashLong("hello") // UTF-8 encoding of the text
val fromBytes: Int = XxHash32().hashInt(byteArrayOf(1, 2, 3))
```

### Streaming

A `Digest` absorbs data incrementally.
Numbers are absorbed little-endian, text as UTF-8, and digesting does not modify the state:

```kotlin
val digest = murmur.newDigest()
digest.update(42).update("name").update(3.14)
val bytes: ByteArray = digest.digest() // big-endian, 16 bytes for a 128-bit hash
val low: Long = digest.digestLong() // the low 64 bits
digest.update(true) // more data can be absorbed afterward
```

### Structured values

`updateValue` and `hashValueLong`/`hashValueInt` hash arbitrary values, including collections, maps, arrays,
ranges, `Uuid`, `Duration`, `Instant`, `Result`, `Regex`, and enums.
Each value is prefixed by a type tag, so that, for instance, `listOf(1, 2)` and `listOf(12)` hash differently.
Hashing never fails: types the library does not know fall back to their `toString()`.

Types can hash themselves by implementing `Hashable`:

```kotlin
class Color(val red: Int, val green: Int, val blue: Int) : Hashable {
    context(registry: FunnelRegistry)
    override fun hashInto(digest: Digest) {
        digest.update(red).update(green).update(blue)
    }
}
```

Types you do not own can be hashed through a `Funnel` in a `FunnelRegistry`:

```kotlin
val registry = FunnelRegistry.build {
    register<Point> { digest, point -> digest.update(point.x).update(point.y) }
}
murmur.hashValueLong(listOf(Point(1.0, 2.0), null, "label"), registry)
```

The registry is a context parameter of `updateValue`, so funnels and `Hashable` implementations can
hash their nested values with `digest.updateValue(...)` using the same registry.

See the documentation of `updateValue` for the exact encoding and its caveats.
In particular, hash-based sets and maps may iterate in different orders on different targets,
and the `toString()` of lambdas, of classes that do not override it, and of floating point numbers on JavaScript
differ across targets or runs: implement `Hashable` or register a `Funnel` for such types.

## Stability

Hashes are identical on every target, and are part of the public API:
changing the output of an algorithm or of the structured encoding is a breaking change, released as a new major
version.

## Building and benchmarking

Gradle needs JDK 17 or newer to run:

```shell
./gradlew build                                # build and test on every target the host supports
./gradlew benchmark -Pbenchmark.quick=true     # smoke run of the benchmarks, written to benchmarks/build
./gradlew benchmark                            # full run, appended to the published results in docs/benchmarks
```

The benchmarks accept `-Pbenchmark.targets=jvm,js,wasmJs,wasmWasi,native` to run a subset of the targets,
and `-Pbenchmark.machine="label"` to label the machine.
Full runs should be executed on an otherwise idle machine.
See [AGENTS.md](AGENTS.md) for the contribution rules.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
