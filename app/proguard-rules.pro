-keep class com.google.crypto.tink.** { *; }
-keep class org.bouncycastle.** { *; }
-dontwarn javax.naming.**

# Room（Release 下勿裁剪生成的实现类）
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keep class com.example.vault.data.VaultDatabase_Impl { *; }

# kotlinx.serialization：避免 R8 移除 $$serializer / 字段名导致解密失败
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class **$$serializer { <init>(...); }
-keep @kotlinx.serialization.Serializable class com.example.vault.crypto.** { <fields>; }
