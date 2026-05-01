package com.example.vault

import android.app.Application

class VaultApp : Application() {
    @Volatile
    var session: VaultSession? = null
}
