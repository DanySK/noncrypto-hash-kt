package org.danilopianini.noncryptohash.common

import org.danilopianini.noncryptohash.Digest

/**
 * A [Digest] for hashes that process blocks of [blockSize] bytes, but end by reading the last bytes of the input,
 * which may overlap blocks already processed (such as XXH3).
 *
 * It processes a block only when more input follows it, so that at least one byte is always pending,
 * and keeps the last [lookback] bytes of the last processed block before the pending ones:
 * the last `n <= lookback` bytes of the input are always contiguous in the buffer.
 */
abstract class BlockBufferDigest internal constructor(private val blockSize: Int, private val lookback: Int) :
    LongLaneDigest() {

    /**
     * The last [lookback] bytes processed, followed by the [buffered] pending bytes.
     */
    internal val buffer: ByteArray = ByteArray(lookback + blockSize)

    /**
     * The number of pending bytes, at most [blockSize].
     */
    internal var buffered: Int = 0
        private set

    /**
     * The total number of bytes absorbed.
     */
    internal var length: Long = 0
        private set

    final override fun absorb(value: Long, width: Int) {
        for (byte in 0 until width) {
            if (buffered == blockSize) {
                processBuffer()
            }
            buffer[lookback + buffered++] = (value ushr (byte * Byte.SIZE_BITS)).toByte()
        }
        length += width
    }

    final override fun reset(): Digest = apply {
        buffered = 0
        length = 0
        resetBlocks()
    }

    final override fun update(bytes: ByteArray, offset: Int, length: Int): Digest = apply {
        requireRange(bytes, offset, length)
        this.length += length
        var index = offset
        val end = offset + length
        if (buffered + length > blockSize) {
            // More input follows the pending bytes: fill them up, and process them
            val fill = blockSize - buffered
            bytes.copyInto(buffer, lookback + buffered, index, index + fill)
            index += fill
            buffered = blockSize
            processBuffer()
            if (end - index > blockSize) {
                // Process every block followed by more input directly, and keep the end of the last one
                val blocks = (end - index - 1) / blockSize
                processBlocks(bytes, index, blocks)
                index += blocks * blockSize
                bytes.copyInto(buffer, 0, index - lookback, index)
            }
        }
        bytes.copyInto(buffer, lookback + buffered, index, end)
        buffered += end - index
    }

    /**
     * Processes [count] blocks of [input], starting at [offset].
     */
    internal abstract fun processBlocks(input: ByteArray, offset: Int, count: Int)

    /**
     * Restores the initial state of the block processing.
     */
    internal abstract fun resetBlocks()

    private fun processBuffer() {
        processBlocks(buffer, lookback, 1)
        buffer.copyInto(buffer, 0, blockSize, lookback + blockSize)
        buffered = 0
    }
}
