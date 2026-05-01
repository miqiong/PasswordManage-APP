package com.example.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.SecureRandom

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MasterPasswordVerifierTest {

    private val verifier = MasterPasswordVerifier()
    private val random = SecureRandom()

    @Test
    fun samePassword_sameSalt_sameVerifier() {
        val salt = ByteArray(16).also { random.nextBytes(it) }
        val pwd = "correct horse battery staple".toByteArray(Charsets.UTF_8)
        val (_, v1) = verifier.deriveKekAndVerifier(pwd, salt)
        val (_, v2) = verifier.deriveKekAndVerifier(pwd, salt)
        assertArrayEquals(v1, v2)
        SecureMemoryUtils.wipe(pwd)
    }

    @Test
    fun wrongPassword_failsVerifier() {
        val salt = ByteArray(16).also { random.nextBytes(it) }
        val good = "secret-a".toByteArray(Charsets.UTF_8)
        val bad = "secret-b".toByteArray(Charsets.UTF_8)
        val (_, stored) = verifier.deriveKekAndVerifier(good, salt)
        assertTrue(verifier.verifyMasterPassword(good, salt, stored))
        assertFalse(verifier.verifyMasterPassword(bad, salt, stored))
        SecureMemoryUtils.wipe(good)
        SecureMemoryUtils.wipe(bad)
    }
}
