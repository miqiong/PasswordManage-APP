package com.example.vault.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface VaultRecordDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: VaultRecordEntity)

    @Query("SELECT * FROM vault_records WHERE record_id = :recordId LIMIT 1")
    suspend fun getById(recordId: String): VaultRecordEntity?

    @Query("SELECT * FROM vault_records WHERE deleted = 0 ORDER BY updated_at DESC")
    suspend fun listActive(): List<VaultRecordEntity>
}
