package com.example.vault.crypto

import com.google.crypto.tink.subtle.AesGcmJce
import java.security.SecureRandom

/**
 * PRD §一.12 / §3.4：AES-256-GCM AEAD，通过 **Google Tink** `AesGcmJce`（非手写 GCM）。
 * ciphertext 存储格式：**nonce(12) || ciphertext||tag**（与 decrypt 输入一致）。
 *
 * **日志**：禁止记录密钥、nonce、明文或完整密文。
 */
class CryptoManager {
    private val secureRandom = SecureRandom()

    fun randomBytes(length: Int): ByteArray {
        require(length > 0)
        return ByteArray(length).also { secureRandom.nextBytes(it) }
    }

    /**
     * Tink `AesGcmJce.encrypt` 输出为 **nonce(12) || ciphertext||tag**。
     * 落库时拆成独立 `payload_nonce` 与 `encrypted_payload`（PRD §3.4）。
     */
    fun seal(key32: ByteArray, plaintext: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
        require(key32.size == 32) { "invalid key length" }
        val aead = AesGcmJce(key32)
        val combined = aead.encrypt(plaintext, aad)
        return try {
            require(combined.size > 12) { "invalid AEAD output" }
            val nonce = combined.copyOfRange(0, 12)
            val ciphertextWithTag = combined.copyOfRange(12, combined.size)
            nonce to ciphertextWithTag
        } finally {
            SecureMemoryUtils.wipe(combined)
        }
    }

    fun open(key32: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray, aad: ByteArray): ByteArray {
        require(key32.size == 32)
        require(nonce.size == 12)
        val aead = AesGcmJce(key32)
        val combined = ByteArray(nonce.size + ciphertextWithTag.size)
        System.arraycopy(nonce, 0, combined, 0, nonce.size)
        System.arraycopy(ciphertextWithTag, 0, combined, nonce.size, ciphertextWithTag.size)
        return try {
            aead.decrypt(combined, aad)
        } finally {
            SecureMemoryUtils.wipe(combined)
        }
    }

    /** 包装 DEK：返回 (dek_nonce, dek_wrapped_ct) */
    fun wrapDek(kek: ByteArray, dek: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> =
        seal(kek, dek, aad)

    fun unwrapDek(kek: ByteArray, dekNonce: ByteArray, dekWrapped: ByteArray, aad: ByteArray): ByteArray =
        open(kek, dekNonce, dekWrapped, aad)
}
