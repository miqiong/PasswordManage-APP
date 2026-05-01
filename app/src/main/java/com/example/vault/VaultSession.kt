package com.example.vault

import com.example.vault.crypto.CryptoManager
import com.example.vault.crypto.MasterPasswordVerifier
import com.example.vault.crypto.RecordEncryptor
import com.example.vault.crypto.SecureMemoryUtils
import com.example.vault.data.VaultDatabase
import com.example.vault.data.VaultRepository

class VaultSession(
    val kek: ByteArray,
    val db: VaultDatabase,
    val repo: VaultRepository,
    val crypto: CryptoManager,
    val enc: RecordEncryptor,
    val mpv: MasterPasswordVerifier
) {
    fun lock() {
        SecureMemoryUtils.wipe(kek)
        db.close()
    }
}
