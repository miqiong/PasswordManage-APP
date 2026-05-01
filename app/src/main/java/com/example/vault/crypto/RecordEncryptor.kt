package com.example.vault.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import java.io.ByteArrayInputStream

/**
 * PRD §三：payload 用 DEK；DEK 用 KEK 包装；AAD 含 record_id|version|updated_at。
 *
 * **日志**：禁止记录密钥、主密码或解密后的 payload。
 *
 * ### PlainRecord 与 String 安全边界
 * 解密后的业务结构字段为 Kotlin [String]（JVM/ART 堆上 **不可** 安全清零）。
 * `password` 等敏感字段仅允许**短时**存在于调用栈内用于展示或剪贴板，
 * **不得**写入 [androidx.lifecycle.ViewModel]、单例或 savedState 等长生命周期状态；
 * 需要长期展示时只保留密文行 [EncryptedRecordRow]，解锁后再解密。
 */
@Serializable
data class PlainRecord(
    val title: String,
    val username: String,
    val password: String,
    val url: String,
    val note: String,
    val tags: List<String> = emptyList()
)

data class EncryptedRecordRow(
    val recordId: String,
    val encryptedPayload: ByteArray,
    val payloadNonce: ByteArray,
    val dekWrapped: ByteArray,
    val dekNonce: ByteArray,
    val version: Int,
    val updatedAt: String,
    val deleted: Boolean
)

class RecordEncryptor(
    private val crypto: CryptoManager,
    private val json: Json = Json { ignoreUnknownKeys = true }
) {

    fun buildAad(recordId: String, version: Int, updatedAt: String): ByteArray =
        "$recordId|$version|$updatedAt".toByteArray(Charsets.UTF_8)

    fun encrypt(recordId: String, plain: PlainRecord, kek: ByteArray, version: Int, updatedAt: String): EncryptedRecordRow {
        val aad = buildAad(recordId, version, updatedAt)
        var payloadBytes: ByteArray? = null
        var dek: ByteArray? = null
        return try {
            payloadBytes = json.encodeToString(plain).toByteArray(Charsets.UTF_8)
            dek = crypto.randomBytes(32)
            val (payloadNonce, encPayload) = crypto.seal(dek, payloadBytes, aad)
            val (dekNonce, dekWrapped) = crypto.wrapDek(kek, dek, aad)
            EncryptedRecordRow(
                recordId = recordId,
                encryptedPayload = encPayload,
                payloadNonce = payloadNonce,
                dekWrapped = dekWrapped,
                dekNonce = dekNonce,
                version = version,
                updatedAt = updatedAt,
                deleted = false
            )
        } finally {
            SecureMemoryUtils.wipe(payloadBytes)
            SecureMemoryUtils.wipe(dek)
            SecureMemoryUtils.wipe(aad)
        }
    }

    fun decrypt(row: EncryptedRecordRow, kek: ByteArray): PlainRecord {
        val aad = buildAad(row.recordId, row.version, row.updatedAt)
        var dek: ByteArray? = null
        return try {
            dek = crypto.unwrapDek(kek, row.dekNonce, row.dekWrapped, aad)
            val plainBytes = crypto.open(dek, row.payloadNonce, row.encryptedPayload, aad)
            try {
                json.decodeFromStream(PlainRecord.serializer(), ByteArrayInputStream(plainBytes))
            } finally {
                SecureMemoryUtils.wipe(plainBytes)
            }
        } finally {
            SecureMemoryUtils.wipe(dek)
            SecureMemoryUtils.wipe(aad)
        }
    }
}
