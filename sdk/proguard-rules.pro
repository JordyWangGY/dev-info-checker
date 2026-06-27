# SDK 自身 release 构建的混淆规则（阶段一 1.4 会补充字符串加密 / 控制流）
-keepclasseswithmembernames class com.devcheck.nativebridge.** {
    native <methods>;
}
