package com.example.securep2p.protocol

import androidx.compose.ui.graphics.Color

object Constants {
    const val APP_NAME = "SecureP2PChat"
    const val APP_VERSION = "0.9.29.3"
    const val APP_AUTHOR = "AndromedaHK"

    const val PROTOCOL_VERSION = 3
    const val DEFAULT_PORT = 37421
    const val DEFAULT_SIGNAL_PORT = 37422

    const val MSG_KEY_EXCHANGE: Byte = 0x01
    const val MSG_TEXT: Byte = 0x02
    const val MSG_IMAGE: Byte = 0x03
    const val MSG_ACK: Byte = 0x04
    const val MSG_PING: Byte = 0x05
    const val MSG_PONG: Byte = 0x06
    const val MSG_FILE_START: Byte = 0x07
    const val MSG_FILE_CHUNK: Byte = 0x08
    const val MSG_FILE_END: Byte = 0x09
    const val MSG_TYPING: Byte = 0x0A
    const val MSG_DELIVERED: Byte = 0x0B
    const val MSG_READ: Byte = 0x0C
    const val MSG_RATCHET: Byte = 0x0D
    const val MSG_HELLO: Byte = 0x0E
    const val MSG_HELLO_ACK: Byte = 0x0F
    const val MSG_GROUP_TEXT: Byte = 0x10
    const val MSG_GROUP_META: Byte = 0x11
    const val MSG_PAIR_JOINED_NOTIFY: Byte = 0xFE.toByte()

    const val ARGON2_TIME_COST = 3
    const val ARGON2_MEMORY_COST = 65536
    const val ARGON2_PARALLELISM = 4
    const val ARGON2_HASH_LEN = 32

    const val SIGNAL_PEER_TTL = 180
    const val SIGNAL_HEARTBEAT_SECONDS = 15L
    const val RELAY_POLL_INTERVAL_MS = 1500L

    const val FILE_CHUNK_SIZE = 64 * 1024 // 64 KB per chunk for mobile reliability
    const val MAX_FILE_SIZE = 50 * 1024 * 1024 // 50 MB

    // Desktop Theme Colors
    val ColorBgDark = Color(0xFF0A0F1C)
    val ColorBgSecondary = Color(0xFF0D1B2A)
    val ColorBgCard = Color(0xFF12263A)
    val ColorAccent = Color(0xFF00D4FF)
    val ColorAccentHover = Color(0xFF00B4D8)
    val ColorAccentDark = Color(0xFF0077B6)
    val ColorText = Color(0xFFE0E6ED)
    val ColorTextSecondary = Color(0xFF8B9BB4)
    val ColorSuccess = Color(0xFF00F5A0)
    val ColorDanger = Color(0xFFFF4D6D)
    val ColorWarning = Color(0xFFFFB703)
    val ColorBorder = Color(0xFF1B3A4B)
    val ColorBubbleIn = Color(0xFF12263A)
    val ColorBubbleOut = Color(0xFF0077B6)
}
