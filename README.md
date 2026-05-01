# PasswordManage-APP

## 模块
- **加密**：`com.example.vault.crypto`（`CryptoManager` / Tink AES-GCM、`RecordEncryptor`、`MasterPasswordVerifier` / Argon2id + RFC5869 HKDF）
- **主密码验证**：`MasterPasswordVerifier`（仅 verifier）
- **数据库**：`com.example.vault.data`（Room + SQLCipher，`vault_records` + `vault_meta`）
- **单元测试**：`src/test/java`（Robolectric）

## 运行单元测试
需本机 **JDK 17+**、Android SDK。在项目根执行：

```bash
./gradlew :app:testDebugUnitTest
```

（若无 Gradle Wrapper，可用 Android Studio 打开工程后同步并运行 `test`。）

## 建表 SQL 参考
见 `schema/vault_schema.sql`。
