package com.example.vault.crypto

import java.util.Arrays

/**
 * PRD §一.15：使用后必须清理敏感 ByteArray。
 */
object SecureMemoryUtils {
    fun wipe(bytes: ByteArray?) {
        if (bytes == null) return
        Arrays.fill(bytes, 0.toByte())
    }
}
