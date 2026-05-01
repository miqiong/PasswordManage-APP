package com.example.vault.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

/**
 * PRD §二：Argon2id（BouncyCastle）+ HKDF-SHA256（RFC5869，与 PC 端一致）+ verifier。
 *
 * **日志策略**：禁止在此类或调用链中记录 [password]、[ByteArray] 密钥材料或 verifier 原文。
 */
class MasterPasswordVerifier {

    companion object {
        private const val MASTER_KEY_LEN = 32
        private const val SALT_LEN = 16
        private val INFO_KEK = "vault-kek-v1".toByteArray(Charsets.UTF_8)
        private val INFO_VERIFIER_KEY = "vault-verifierkey-v1".toByteArray(Charsets.UTF_8)
        private val INFO_DB_KEY = "vault-sqlcipher-v1".toByteArray(Charsets.UTF_8)
        private val VERIFIER_LABEL = "vault-verifier-v1".toByteArray(Charsets.UTF_8)
        private const val MEMORY_KB = 131072
        private const val ITERATIONS = 3
        private const val PARALLELISM = 2
    }

    fun deriveMasterKey(password: ByteArray, salt: ByteArray): ByteArray {
        require(salt.size == SALT_LEN) { "invalid salt length" }
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withMemoryAsKB(MEMORY_KB)
            .withIterations(ITERATIONS)
            .withParallelism(PARALLELISM)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val out = ByteArray(MASTER_KEY_LEN)
        gen.generateBytes(password, out)
        return out
    }

    /** RFC5869 HKDF-SHA256，Extract 使用 HMAC-SHA256(key=32*0x00, data=IKM)（与 PC 一致）。 */
    fun hkdfSha256(ikm: ByteArray, info: ByteArray, length: Int = MASTER_KEY_LEN): ByteArray {
        val prk = hkdfExtractSha256(ikm)
        return try {
            hkdfExpandSha256(prk, info, length)
        } finally {
            SecureMemoryUtils.wipe(prk)
        }
    }

    private fun hkdfExtractSha256(ikm: ByteArray): ByteArray {
        val zeroKey = ByteArray(32)
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(zeroKey, "HmacSHA256"))
            mac.doFinal(ikm)
        } finally {
            SecureMemoryUtils.wipe(zeroKey)
        }
    }

    /**
     * HKDF-Expand；输出写入固定 [ByteArray]，**禁止**使用 [java.util.ArrayList] 等结构累积密钥字节。
     * 链值 [t] 在 [finally] 中清零。
     */
    private fun hkdfExpandSha256(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val result = ByteArray(length)
        var t = ByteArray(0)
        try {
            var counter: Byte = 1
            var offset = 0
            while (offset < length) {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(prk, "HmacSHA256"))
                mac.update(t)
                mac.update(info)
                mac.update(byteArrayOf(counter))
                val newT = mac.doFinal()
                SecureMemoryUtils.wipe(t)
                t = newT
                val need = length - offset
                val take = min(t.size, need)
                System.arraycopy(t, 0, result, offset, take)
                offset += take
                counter = (counter + 1).toByte()
            }
        } finally {
            SecureMemoryUtils.wipe(t)
        }
        return result
    }

    fun deriveKek(masterKey: ByteArray): ByteArray = hkdfSha256(masterKey, INFO_KEK)

    fun deriveVerifierKey(masterKey: ByteArray): ByteArray = hkdfSha256(masterKey, INFO_VERIFIER_KEY)

    /** 由 KEK 派生 SQLCipher 文件口令（32 字节），不落盘。 */
    fun deriveDatabasePassphrase(kek: ByteArray): ByteArray = hkdfSha256(kek, INFO_DB_KEY, MASTER_KEY_LEN)

    fun buildVerifier(verifierKey: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(verifierKey, "HmacSHA256"))
        return mac.doFinal(VERIFIER_LABEL)
    }

    fun verifyMasterPassword(password: ByteArray, salt: ByteArray, storedVerifier: ByteArray): Boolean {
        val mk = deriveMasterKey(password, salt)
        var candidate: ByteArray? = null
        return try {
            val vk = deriveVerifierKey(mk)
            try {
                candidate = buildVerifier(vk)
                constantTimeEquals(candidate, storedVerifier)
            } finally {
                SecureMemoryUtils.wipe(vk)
            }
        } finally {
            SecureMemoryUtils.wipe(mk)
            SecureMemoryUtils.wipe(candidate)
        }
    }

    fun deriveKekAndVerifier(password: ByteArray, salt: ByteArray): Pair<ByteArray, ByteArray> {
        val mk = deriveMasterKey(password, salt)
        return try {
            val kek = deriveKek(mk)
            val vk = deriveVerifierKey(mk)
            val verifier = buildVerifier(vk)
            SecureMemoryUtils.wipe(vk)
            Pair(kek, verifier)
        } finally {
            SecureMemoryUtils.wipe(mk)
        }
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var x = 0
        for (i in a.indices) x = x or (a[i].toInt() xor b[i].toInt())
        return x == 0
    }
}
