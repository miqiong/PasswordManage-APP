package com.example.vault.data.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * PRD §三.2 / 附录 C：`vault_records`。
 */
@Entity(tableName = "vault_records")
data class VaultRecordEntity(
    @PrimaryKey
    @ColumnInfo(name = "record_id")
    val recordId: String,
    @ColumnInfo(name = "encrypted_payload")
    val encryptedPayload: ByteArray,
    @ColumnInfo(name = "payload_nonce")
    val payloadNonce: ByteArray,
    @ColumnInfo(name = "dek_wrapped")
    val dekWrapped: ByteArray,
    @ColumnInfo(name = "dek_nonce")
    val dekNonce: ByteArray,
    @ColumnInfo(name = "version")
    val version: Int,
    @ColumnInfo(name = "updated_at")
    val updatedAt: String,
    @ColumnInfo(name = "deleted")
    val deleted: Boolean
)
