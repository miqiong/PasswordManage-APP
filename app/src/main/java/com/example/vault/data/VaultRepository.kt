package com.example.vault.data

import com.example.vault.crypto.EncryptedRecordRow
import com.example.vault.data.db.VaultRecordEntity

/**
 * 仅访问密文记录表；salt/verifier 由 [MetaStore] 管理。
 */
class VaultRepository(
    private val db: VaultDatabase
) {
    private val recordDao get() = db.vaultRecordDao()

    suspend fun listRecords(): List<EncryptedRecordRow> =
        recordDao.listActive().map { e ->
            EncryptedRecordRow(
                recordId = e.recordId,
                encryptedPayload = e.encryptedPayload,
                payloadNonce = e.payloadNonce,
                dekWrapped = e.dekWrapped,
                dekNonce = e.dekNonce,
                version = e.version,
                updatedAt = e.updatedAt,
                deleted = e.deleted
            )
        }

    suspend fun upsertRecord(row: EncryptedRecordRow) {
        recordDao.upsert(
            VaultRecordEntity(
                recordId = row.recordId,
                encryptedPayload = row.encryptedPayload,
                payloadNonce = row.payloadNonce,
                dekWrapped = row.dekWrapped,
                dekNonce = row.dekNonce,
                version = row.version,
                updatedAt = row.updatedAt,
                deleted = row.deleted
            )
        )
    }

    suspend fun getRecord(recordId: String): EncryptedRecordRow? {
        val e = recordDao.getById(recordId) ?: return null
        return EncryptedRecordRow(
            recordId = e.recordId,
            encryptedPayload = e.encryptedPayload,
            payloadNonce = e.payloadNonce,
            dekWrapped = e.dekWrapped,
            dekNonce = e.dekNonce,
            version = e.version,
            updatedAt = e.updatedAt,
            deleted = e.deleted
        )
    }
}
