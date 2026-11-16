package org.danilopianini.noncryptohash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class StructuredHashingTest {

    @Test
    @Suppress("InvalidRange", "EmptyRange") // Empty on purpose
    fun `all empty ranges hash the same`() {
        assertEquals(structured(5..1), structured(3..0))
        assertEquals(structured(1.0..0.0), structured(Double.NaN..1.0))
        assertEquals(structured(1.0..<1.0), structured(2.0..<0.0))
    }

    @Test
    fun `any char sequence hashes like the equivalent string`() {
        assertEquals(structured("abc"), structured(StringBuilder("abc")))
    }

    @Test
    fun `arrays are hashed by content and element type`() {
        assertEquals(structured(intArrayOf(1, 2)), structured(intArrayOf(1, 2)))
        assertEquals(structured(arrayOf<Any>("a", 1)), structured(arrayOf<Any>("a", 1)))
        assertNotEquals(structured(intArrayOf(1, 2)), structured(longArrayOf(1, 2)))
    }

    @Test
    fun `classes are hashed by simple name`() {
        assertEquals(structured(Point::class), structured(Point(1, 2)::class))
        assertNotEquals(structured(Point::class), structured(Box::class))
    }

    @Test
    fun `closed and open-ended floating point ranges differ`() {
        assertEquals(structured(0.0..1.0), structured(0.0..1.0))
        assertNotEquals(structured(0.0..1.0), structured(0.0..<1.0))
    }

    @Test
    fun `durations and instants are hashed with nanosecond precision`() {
        assertNotEquals(structured(1.seconds), structured(1.seconds + 1.nanoseconds))
        assertNotEquals(
            structured(Instant.fromEpochSeconds(1, 0)),
            structured(Instant.fromEpochSeconds(1, 1)),
        )
    }

    @Test
    fun `enums are hashed by ordinal`() {
        assertNotEquals(structured(Color.RED), structured(Color.GREEN))
        assertEquals(raw { update(35.toByte()).update(1) }, structured(Color.GREEN))
    }

    @Test
    fun `funnels pass the registry in context to nested values`() {
        val registry = FunnelRegistry.build {
            register<Point> { digest, point -> digest.update(point.x) }
            register<Segment> { digest, segment -> digest.updateValue(listOf(segment.from, segment.to)) }
        }
        val expected = raw {
            update(1.toByte()) // Segment: custom
            update(47.toByte()) // List: iterable
            update(1.toByte()).update(1) // Point: custom
            update(1.toByte()).update(3) // Point: custom
            update(2) // List size
        }
        assertEquals(expected, structured(Segment(Point(1, 2), Point(3, 4)), registry))
    }

    @Test
    fun `hashable values hash themselves`() {
        assertEquals(raw { update(1.toByte()).updateValue("x", FunnelRegistry.EMPTY) }, structured(Box("x")))
    }

    @Test
    fun `hashables pass the registry in context to nested values`() {
        val registry = FunnelRegistry.build { register<Point> { digest, point -> digest.update(point.y) } }
        assertEquals(raw { update(1.toByte()).update(1.toByte()).update(2) }, structured(Box(Point(1, 2)), registry))
    }

    @Test
    fun `huge ranges are hashed without iterating over them`() {
        assertEquals(structured(0..Int.MAX_VALUE), structured(0..Int.MAX_VALUE))
        assertEquals(structured(0L..Long.MAX_VALUE), structured(0L..Long.MAX_VALUE))
        assertNotEquals(structured(0..10 step 2), structured(0..10))
    }

    @Test
    fun `later registrations take precedence over earlier ones`() {
        val base = FunnelRegistry.build { register<Collection<*>> { digest, _ -> digest.update(1) } }
        val extended = base.extend { register<List<*>> { digest, _ -> digest.update(2) } }
        assertEquals(raw { update(1.toByte()).update(1) }, structured(listOf(0), base))
        assertEquals(raw { update(1.toByte()).update(2) }, structured(listOf(0), extended))
        assertEquals(raw { update(1.toByte()).update(1) }, structured(setOf(0), extended))
    }

    @Test
    fun `lists of strings split at different points do not collide`() {
        assertNotEquals(structured(listOf("a\u0000", "b")), structured(listOf("a", "\u0000b")))
        assertNotEquals(structured(listOf("ab", "c")), structured(listOf("a", "bc")))
    }

    @Test
    fun `maps hash both keys and values`() {
        assertEquals(structured(mapOf(1 to "a")), structured(mapOf(1 to "a")))
        assertNotEquals(structured(mapOf(1 to "a")), structured(mapOf(1 to "b")))
    }

    @Test
    fun `nested lists with the same flattened content do not collide`() {
        assertNotEquals(structured(listOf(listOf(0), emptyList())), structured(listOf(emptyList(), listOf(0))))
        assertNotEquals(structured(listOf(listOf(1), listOf(2))), structured(listOf(listOf(1, 2))))
    }

    @Test
    fun `nulls in different positions do not collide`() {
        assertNotEquals(structured(Pair(null, -1)), structured(Pair(-1, null)))
    }

    @Test
    fun `regexes hash pattern and options regardless of option order`() {
        assertEquals(structured(Regex("a+")), structured(Regex("a+")))
        assertNotEquals(structured(Regex("a+")), structured(Regex("a+", RegexOption.IGNORE_CASE)))
        assertEquals(
            structured(Regex("a+", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE))),
            structured(Regex("a+", setOf(RegexOption.MULTILINE, RegexOption.IGNORE_CASE))),
        )
    }

    @Test
    fun `results distinguish success from failure and from plain values`() {
        assertNotEquals(structured(Result.success(null)), structured(null))
        assertNotEquals(structured(Result.success(1)), structured(Result.success(2)))
        assertEquals(
            structured(Result.failure<Int>(IllegalStateException("x"))),
            structured(Result.failure<Int>(IllegalStateException("x"))),
        )
        assertNotEquals(
            structured(Result.failure<Int>(IllegalStateException("x"))),
            structured(Result.failure<Int>(IllegalArgumentException("x"))),
        )
    }

    @Test
    fun `the registry overrides open types but not final ones`() {
        val registry = FunnelRegistry.build {
            register<Point> { digest, point -> digest.update(point.x).update(point.y) }
            register<List<*>> { digest, _ -> digest.update(42) }
        }
        assertEquals(raw { update(1.toByte()).update(1).update(2) }, structured(Point(1, 2), registry))
        assertEquals(raw { update(1.toByte()).update(42) }, structured(listOf(1, 2), registry))
        // Final types are never overridden
        assertEquals(structured(1), structured(1, registry))
    }

    @Test
    fun `unknown types fall back to their string representation`() {
        assertEquals(structured(Point(1, 2)), structured(Point(1, 2)))
        assertNotEquals(structured(Point(1, 2)), structured("Point(x=1, y=2)"))
    }

    @OptIn(ExperimentalUuidApi::class)
    @Test
    fun `uuids are hashed by value`() {
        val uuid = Uuid.parse("550e8400-e29b-41d4-a716-446655440000")
        assertEquals(structured(uuid), structured(Uuid.parse(uuid.toString())))
        assertNotEquals(structured(uuid), structured(Uuid.NIL))
    }

    @Test
    fun `values of different types with the same bytes do not collide`() {
        assertNotEquals(structured(1.toShort()), structured(listOf(1.toByte())))
        assertNotEquals(structured(null), structured(0.toByte()))
        assertNotEquals(structured(listOf(1, 2, 3)), structured(1..3))
        assertNotEquals(structured(1..3), structured(1u..3u))
    }

    private class Box(val content: Any?) : Hashable {
        context(registry: FunnelRegistry)
        override fun hashInto(digest: Digest) {
            digest.updateValue(content)
        }
    }

    private enum class Color { RED, GREEN }

    private data class Point(val x: Int, val y: Int)

    private data class Segment(val from: Point, val to: Point)
}
