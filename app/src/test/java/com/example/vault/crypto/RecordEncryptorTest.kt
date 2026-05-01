package com.example.vault.crypto

import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RecordEncryptorTest {

    @Test
    fun encryptDecrypt_roundTrip() {
        val crypto = CryptoManager()
        val encryptor = RecordEncryptor(crypto)
        val kek = crypto.randomBytes(32)
        val recordId = UUID.randomUUID().toString()
        val updatedAt = "2026-05-01T12:00:00Z"
        val plain = PlainRecord(
            title = "Ex",
            username = "u",
            password = "p",
            url = "https://example.com",
            note = "n",
            tags = listOf("a", "b")
        )
        val row = encryptor.encrypt(recordId, plain, kek, version = 1, updatedAt = updatedAt)
        val back = encryptor.decrypt(row, kek)
        assertEquals(plain, back)
        SecureMemoryUtils.wipe(kek)
    }
}
