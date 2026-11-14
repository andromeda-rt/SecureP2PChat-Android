package com.example.securep2p.protocol

object PairCode {
    private val validCode = Regex("[A-HJ-NP-Z2-9]{6}")

    fun normalize(input: String): String? {
        val normalized = input
            .filterNot { it.isWhitespace() || it == '-' }
            .uppercase()
        return normalized.takeIf(validCode::matches)
    }
}
