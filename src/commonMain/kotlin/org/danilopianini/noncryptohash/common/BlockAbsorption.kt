package org.danilopianini.noncryptohash.common

/**
 * Absorbs [length] bytes of [bytes], starting at [offset], into a digest that processes blocks of [blockSize] bytes.
 * First completes the pending block (if [hasPending]) byte by byte through [absorbByte],
 * then passes the range of the whole blocks that follow to [blocks],
 * and finally buffers the remaining bytes through [absorbByte].
 * [absorbByte] receives the bytes as unsigned values.
 */
internal inline fun absorbInBlocks(
    bytes: ByteArray,
    offset: Int,
    length: Int,
    blockSize: Int,
    hasPending: () -> Boolean,
    absorbByte: (Int) -> Unit,
    blocks: (start: Int, end: Int) -> Unit,
) {
    requireRange(bytes, offset, length)
    var index = offset
    val end = offset + length
    while (hasPending() && index < end) {
        absorbByte(bytes[index++].toInt() and BYTE_MASK)
    }
    val blocksEnd = index + (end - index) / blockSize * blockSize
    if (blocksEnd > index) {
        blocks(index, blocksEnd)
        index = blocksEnd
    }
    while (index < end) {
        absorbByte(bytes[index++].toInt() and BYTE_MASK)
    }
}

private const val BYTE_MASK: Int = 0xFF
