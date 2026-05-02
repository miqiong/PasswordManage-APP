package com.example.vault

import android.app.Application
import net.sqlcipher.database.SQLiteDatabase

class VaultApp : Application() {

    @Volatile
    var session: VaultSession? = null

    override fun onCreate() {
        super.onCreate()
        // 尽早、单进程主线程初始化 SQLCipher native，避免首次开库在后台线程 loadLibs 导致偶发 UnsatisfiedLinkError。
        SQLiteDatabase.loadLibs(this)
    }
}
