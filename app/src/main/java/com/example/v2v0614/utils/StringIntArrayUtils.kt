package com.example.v2v0614.utils

object StringIntArrayUtils {
    /**
     * 将字符串编码为 UTF-8 字节，并按每 4 字节转换为 Int 数组。
     */
    fun stringToIntArray(message: String): List<Int> {
        val bytes = message.toByteArray(Charsets.UTF_8)
        val padded = bytes + ByteArray((4 - bytes.size % 4) % 4) // 补齐为4的倍数
        return padded.toList()
            .chunked(4)
            .map { (b0, b1, b2, b3) ->
                (b0.toInt() and 0xFF shl 24) or
                (b1.toInt() and 0xFF shl 16) or
                (b2.toInt() and 0xFF shl 8) or
                (b3.toInt() and 0xFF)
            }
    }

    /**
     * 将 Int 数组还原为字节数组，并转换回 UTF-8 字符串。
     */
    fun intArrayToString(messageArray: List<Int>): String {
        val bytes = mutableListOf<Byte>()
        for (value in messageArray) {
            bytes.add((value shr 24).toByte())
            bytes.add((value shr 16).toByte())
            bytes.add((value shr 8).toByte())
            bytes.add(value.toByte())
        }
        // 去除多余的补零字节（\u0000）
        return bytes.toByteArray().toString(Charsets.UTF_8).trimEnd('\u0000')
    }
} 