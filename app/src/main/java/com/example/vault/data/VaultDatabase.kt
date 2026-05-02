package com.example.vault.data

import android.content.Context
import android.util.Base64
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.example.vault.data.db.VaultRecordDao
import com.example.vault.data.db.VaultRecordEntity
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory

/**
 * PRD §一.9：Room + SQLCipher（仅 `vault_records`）。口令为 32 字节经 Base64 的 ASCII（与 PC 一致）。
 *
 * **迁移**：仅注册显式 [Migration]；**禁止** [RoomDatabase.Builder.fallbackToDestructiveMigration]，避免静默删库。
 */
@Database(
    entities = [VaultRecordEntity::class],
    version = 3,
    exportSchema = false
)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun vaultRecordDao(): VaultRecordDao

    companion object {

        /** v1 含 `vault_meta`；v2 移除该表，salt/verifier 仅存在于 [MetaStore]。 */
        val MIGRATION_1_2: Migration = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("DROP TABLE IF EXISTS vault_meta")
            }
        }

        /** v2→v3：当前无 DDL 变更；后续索引/列调整请写在此，勿启用 destructive fallback。 */
        val MIGRATION_2_3: Migration = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // 占位：例如 db.execSQL("CREATE INDEX IF NOT EXISTS ...")
            }
        }

        fun create(context: Context, rawDbKey32: ByteArray): VaultDatabase {
            SQLiteDatabase.loadLibs(context)
            val passphraseAscii =
                Base64.encodeToString(rawDbKey32, Base64.NO_WRAP).toByteArray(Charsets.US_ASCII)
            // [SupportFactory] 保存的是同一 byte[] 引用；Room 首次访问 DB 时才真正打开。
            // 若在此处 wipe，口令在打开前已被清零，会触发 “passphrase appears to be cleared” 或解密失败。
            // 默认 clearPassphrase=true：SQLCipher 在首次成功打开后会自行清零该数组。
            val factory = SupportFactory(passphraseAscii)
            return Room.databaseBuilder(
                context.applicationContext,
                VaultDatabase::class.java,
                "vault.db"
            )
                .openHelperFactory(factory)
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
                .build()
        }
    }
}
