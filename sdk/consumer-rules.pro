# 随 AAR 下发给集成方的混淆规则

# 公共 API 保留
-keep public class com.devcheck.DevCheck { public *; }
-keep public class com.devcheck.DevCheckConfig { *; }
-keep public class com.devcheck.protocol.** { *; }

# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class **$$serializer { *; }
-keepclassmembers @kotlinx.serialization.Serializable class com.devcheck.protocol.** {
    *** Companion;
    *** INSTANCE;
}

# JNI：原生方法签名不可改名
-keepclasseswithmembernames class com.devcheck.nativebridge.** {
    native <methods>;
}
