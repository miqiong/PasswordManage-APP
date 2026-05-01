package com.example.vault.data

import androidx.test.core.app.ApplicationProvider
import com.example.vault.crypto.CryptoManager
import com.example.vault.crypto.MasterPasswordVerifier
import com.example.vault.crypto.PlainRecord
import com.example.vault.crypto.RecordEncryptor
import com.example.vault.crypto.SecureMemoryUtils
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.SecureRandom
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class VaultDatabaseTest {

    @Test
    fun bootstrapAndRecord_roundTrip() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val metaStore = MetaStore(context)

        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val pwd = "unit-test-password".toByteArray(Charsets.UTF_8)
        val mpv = MasterPasswordVerifier()
        val (kek, storedVerifier) = mpv.deriveKekAndVerifier(pwd, salt)
        metaStore.write(salt, storedVerifier)

        val dbKey = mpv.deriveDatabasePassphrase(kek)
        val db = VaultDatabase.create(context, dbKey)
        val repo = VaultRepository(db)

        val crypto = CryptoManager()
        val enc = RecordEncryptor(crypto)
        val recordId = UUID.randomUUID().toString()
        val updatedAt = "2026-05-01T00:00:00Z"
        val row = enc.encrypt(
            recordId,
            PlainRecord("t", "u", "p", "url", "n", emptyList()),
            kek,
            1,
            updatedAt
        )
        repo.upsertRecord(row)
        val loaded = repo.getRecord(recordId)
        assertNotNull(loaded)
        val plain = enc.decrypt(loaded!!, kek)
        assertEquals("t", plain.title)

        SecureMemoryUtils.wipe(pwd)
        SecureMemoryUtils.wipe(kek)
        SecureMemoryUtils.wipe(dbKey)
        db.close()
        metaStore.clear()
    }
}
