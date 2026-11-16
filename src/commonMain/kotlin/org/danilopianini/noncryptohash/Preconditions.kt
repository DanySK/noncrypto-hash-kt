package org.danilopianini.noncryptohash

/**
 * Checks that [destination] has room for [bytes] bytes from [offset].
 */
internal fun requireRoom(destination: ByteArray, offset: Int, bytes: Int) {
    require(offset >= 0 && destination.size - offset >= bytes) {
        "Need $bytes bytes from offset $offset, but the destination has size ${destination.size}"
    }
}

/**
 * Checks that [length] bytes from [offset] are within [bytes].
 */
internal fun requireRange(bytes: ByteArray, offset: Int, length: Int) {
    require(offset >= 0 && length >= 0 && offset <= bytes.size - length) {
        "Invalid range: offset $offset, length $length, size ${bytes.size}"
    }
}
