package com.example.vault.data

import android.content.Context
import com.example.vault.crypto.SecureMemoryUtils
import java.io.File
import java.io.IOException

/**
 * 引导数据：salt(16) + verifier(32)，仅存于应用私有目录。
 * 说明：主加密库为 SQLCipher，开库前需读取 salt/verifier，故与密文库分离存储（后续可改为 EncryptedFile / 硬件绑定）。
 */
class MetaStore(private val context: Context) {
    private val file: File
        get() = File(context.filesDir, FILE_NAME)

    fun exists(): Boolean = file.exists() && file.length() == (SALT_LEN + VERIFIER_LEN).toLong()

    @Throws(IOException::class)
    fun write(salt: ByteArray, verifier: ByteArray) {
        require(salt.size == SALT_LEN && verifier.size == VERIFIER_LEN)
        file.outputStream().use { out ->
            out.write(salt)
            out.write(verifier)
            out.flush()
        }
    }

    fun read(): Pair<ByteArray, ByteArray>? {
        if (!exists()) return null
        var all: ByteArray? = null
        return try {
            all = file.readBytes()
            if (all.size != SALT_LEN + VERIFIER_LEN) return null
            val salt = all.copyOfRange(0, SALT_LEN)
            val verifier = all.copyOfRange(SALT_LEN, all.size)
            Pair(salt, verifier)
        } catch (_: Exception) {
            null
        } finally {
            SecureMemoryUtils.wipe(all)
        }
    }

    fun clear() {
        try {
            if (file.exists()) {
                val junk = ByteArray(file.length().toInt())
                java.security.SecureRandom().nextBytes(junk)
                file.writeBytes(junk)
                file.delete()
                SecureMemoryUtils.wipe(junk)
            }
        } catch (_: Exception) { }
    }

    companion object {
        private const val FILE_NAME = "vault_bootstrap.bin"
        private const val SALT_LEN = 16
        private const val VERIFIER_LEN = 32
    }
}
