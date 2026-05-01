package com.example.vault

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.vault.crypto.CryptoManager
import com.example.vault.crypto.MasterPasswordVerifier
import com.example.vault.crypto.RecordEncryptor
import com.example.vault.crypto.SecureMemoryUtils
import com.example.vault.data.MetaStore
import com.example.vault.data.VaultDatabase
import com.example.vault.data.VaultRepository
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom

/**
 * **禁止**使用 [android.util.Log] 等输出主密码、KEK、[com.example.vault.crypto.PlainRecord] 或任何明文字段。
 * 列表仅展示标题字符串，不持有 [com.example.vault.crypto.PlainRecord] 于 Activity 字段或 ViewModel。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var metaStore: MetaStore
    private lateinit var panelUnlock: View
    private lateinit var panelList: View
    private lateinit var hint: TextView
    private lateinit var inputPassword: TextInputEditText
    private lateinit var btnPrimary: MaterialButton
    private lateinit var textError: TextView
    private lateinit var btnLock: MaterialButton
    private lateinit var recycler: RecyclerView
    private lateinit var textStatus: TextView
    private val adapter = RecordAdapter()
    private var vaultExists = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        metaStore = MetaStore(this)

        panelUnlock = findViewById(R.id.panel_unlock)
        panelList = findViewById(R.id.panel_list)
        hint = findViewById(R.id.text_hint)
        inputPassword = findViewById(R.id.input_password)
        btnPrimary = findViewById(R.id.btn_primary)
        textError = findViewById(R.id.text_error)
        btnLock = findViewById(R.id.btn_lock)
        recycler = findViewById(R.id.recycler)
        textStatus = findViewById(R.id.text_status)

        recycler.layoutManager = LinearLayoutManager(this)
        recycler.adapter = adapter

        refreshUnlockUi()
        btnPrimary.setOnClickListener { onPrimaryClick() }
        btnLock.setOnClickListener { lockVault() }
    }

    private fun refreshUnlockUi() {
        vaultExists = metaStore.exists()
        hint.text = if (vaultExists) "输入主密码以解锁" else "创建主密码（至少 8 位）"
        btnPrimary.text = if (vaultExists) "解锁" else "创建并打开"
        textError.visibility = View.GONE
        inputPassword.text?.clear()
    }

    private fun onPrimaryClick() {
        textError.visibility = View.GONE
        val pwdText = inputPassword.text?.toString().orEmpty()
        if (pwdText.isEmpty() || (!vaultExists && pwdText.length < 8)) {
            textError.text = if (vaultExists) "请输入主密码" else "主密码至少 8 位"
            textError.visibility = View.VISIBLE
            return
        }

        val pwd = pwdText.toByteArray(Charsets.UTF_8)
        try {
            val mpv = MasterPasswordVerifier()
            if (!vaultExists) {
                val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
                try {
                    val (kek, verifier) = mpv.deriveKekAndVerifier(pwd, salt)
                    try {
                        metaStore.write(salt, verifier)
                        openVault(kek, mpv)
                    } finally {
                        SecureMemoryUtils.wipe(verifier)
                        SecureMemoryUtils.wipe(kek)
                    }
                } finally {
                    SecureMemoryUtils.wipe(salt)
                }
            } else {
                val meta = metaStore.read()
                if (meta == null) {
                    textError.text = "无法读取保管库元数据"
                    textError.visibility = View.VISIBLE
                    return
                }
                val (salt, verifier) = meta
                try {
                    if (!mpv.verifyMasterPassword(pwd, salt, verifier)) {
                        textError.text = "主密码错误"
                        textError.visibility = View.VISIBLE
                        return
                    }
                    val mk = mpv.deriveMasterKey(pwd, salt)
                    try {
                        val kek = mpv.deriveKek(mk)
                        try {
                            openVault(kek, mpv)
                        } finally {
                            SecureMemoryUtils.wipe(kek)
                        }
                    } finally {
                        SecureMemoryUtils.wipe(mk)
                    }
                } finally {
                    SecureMemoryUtils.wipe(salt)
                    SecureMemoryUtils.wipe(verifier)
                }
            }
        } finally {
            SecureMemoryUtils.wipe(pwd)
            inputPassword.text?.clear()
        }
    }

    private fun openVault(kek: ByteArray, mpv: MasterPasswordVerifier) {
        val dbKey = mpv.deriveDatabasePassphrase(kek)
        try {
            val db = VaultDatabase.create(applicationContext, dbKey)
            val repo = VaultRepository(db)
            val crypto = CryptoManager()
            val enc = RecordEncryptor(crypto)
            val kekCopy = kek.copyOf()
            (application as VaultApp).session = VaultSession(kekCopy, db, repo, crypto, enc, mpv)

            panelUnlock.visibility = View.GONE
            panelList.visibility = View.VISIBLE
            reloadList()
        } finally {
            SecureMemoryUtils.wipe(dbKey)
        }
    }

    private fun reloadList() {
        val session = (application as VaultApp).session ?: return
        textStatus.text = "加载中…"
        lifecycleScope.launch {
            val rows = withContext(Dispatchers.IO) { session.repo.listRecords() }
            val pairs = mutableListOf<Pair<String, String>>()
            for (row in rows) {
                val title = try {
                    withContext(Dispatchers.Default) {
                        // 仅取 title，不把 PlainRecord 存入 ViewModel / Activity 字段
                        val plain = session.enc.decrypt(row, session.kek)
                        plain.title.ifBlank { row.recordId }
                    }
                } catch (_: Exception) {
                    row.recordId
                }
                pairs.add(row.recordId to title)
            }
            adapter.submit(pairs)
            textStatus.text = if (pairs.isEmpty()) "暂无条目" else "${pairs.size} 条"
        }
    }

    private fun lockVault() {
        (application as VaultApp).session?.lock()
        (application as VaultApp).session = null
        panelList.visibility = View.GONE
        panelUnlock.visibility = View.VISIBLE
        adapter.submit(emptyList())
        refreshUnlockUi()
    }
}
