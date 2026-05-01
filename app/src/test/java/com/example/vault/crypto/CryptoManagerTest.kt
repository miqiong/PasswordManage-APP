package com.example.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CryptoManagerTest {

    private val crypto = CryptoManager()

    @Test
    fun sealOpen_roundTrip() {
        val key = crypto.randomBytes(32)
        val pt = "hello vault".toByteArray(Charsets.UTF_8)
        val aad = "record|1|ts".toByteArray(Charsets.UTF_8)
        val (nonce, ct) = crypto.seal(key, pt, aad)
        val out = crypto.open(key, nonce, ct, aad)
        assertArrayEquals(pt, out)
        SecureMemoryUtils.wipe(key)
    }

    @Test
    fun tamperAad_failsDecrypt() {
        val key = crypto.randomBytes(32)
        val pt = "data".toByteArray(Charsets.UTF_8)
        val aad = "aad-original".toByteArray(Charsets.UTF_8)
        val (nonce, ct) = crypto.seal(key, pt, aad)
        var failed = false
        try {
            crypto.open(key, nonce, ct, "aad-tampered".toByteArray(Charsets.UTF_8))
        } catch (_: Exception) {
            failed = true
        }
        assertTrue("decrypt should fail on wrong AAD", failed)
        SecureMemoryUtils.wipe(key)
    }
}
