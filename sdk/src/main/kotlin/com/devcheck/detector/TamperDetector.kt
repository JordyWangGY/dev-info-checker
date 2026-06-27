package com.devcheck.detector

import android.content.Context
import android.content.pm.PackageManager
import com.devcheck.core.sha256Hex
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** 重打包 / 签名篡改 / 安装来源检测。so 完整性自校验见 1.2 原生层。 */
internal class TamperDetector : Detector {
    override val id = "tamper"
    override val category = Category.TAMPER

    private val knownStores = setOf(
        "com.android.vending", "com.google.android.feedback", "com.amazon.venezia",
        "com.huawei.appmarket", "com.xiaomi.market", "com.heytap.market", "com.oppo.market",
        "com.bbk.appstore", "com.tencent.android.qqdownloader", "com.sec.android.app.samsungapps",
    )

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()

        // 1) 签名比对
        val sigs = signatureSha256(ctx.app)
        val expected = ctx.config.expectedSignatureSha256?.uppercase()?.replace(":", "")
        when {
            expected == null -> out += Signal(
                Signals.TAMPER_SIGNATURE, category, Severity.INFO, 1f, Source.JAVA,
                mapOf("actual_sha256" to sigs.joinToString(), "note" to "set expectedSignatureSha256 to enforce"),
            )
            sigs.none { it == expected } -> out += Signal(
                Signals.TAMPER_SIGNATURE, category, Severity.CRITICAL, 1f, Source.JAVA,
                mapOf("expected" to expected, "actual" to sigs.joinToString()),
            )
        }

        // 签名交叉校验：PM 上报签名 vs 直接解析 APK 文件签名，不一致 = 签名伪造框架
        val apkSigs = runCatching {
            val info = ctx.app.packageManager.getPackageArchiveInfo(
                ctx.app.applicationInfo.sourceDir, PackageManager.GET_SIGNING_CERTIFICATES,
            )
            val signing = info?.signingInfo
            val certs = when {
                signing == null -> emptyArray()
                signing.hasMultipleSigners() -> signing.apkContentsSigners
                else -> signing.signingCertificateHistory
            }
            certs.orEmpty().map { sha256Hex(it.toByteArray()) }
        }.getOrDefault(emptyList())
        if (sigs.isNotEmpty() && apkSigs.isNotEmpty() && sigs.toSet() != apkSigs.toSet()) {
            out += Signal(
                Signals.TAMPER_SIG_SPOOF, category, Severity.HIGH, 0.85f, Source.JAVA,
                mapOf("pm" to sigs.joinToString(), "apk" to apkSigs.joinToString()),
            )
        }

        // 2) 安装来源
        val installer = runCatching {
            ctx.app.packageManager.getInstallSourceInfo(ctx.app.packageName).installingPackageName
        }.getOrNull()
        if (installer == null || installer !in knownStores) {
            out += Signal(
                Signals.TAMPER_INSTALLER, category, Severity.LOW, 0.5f, Source.JAVA,
                mapOf("installer" to (installer ?: "null(sideload)")),
            )
        }

        // 3) .so 自校验：本 SDK 原生库代码段不应「可写且可执行」（原生确认）→ 阻断点
        if (ctx.native.isAvailable && ctx.native.codeWritable()) {
            out += Signal(
                Signals.TAMPER_SO_INTEGRITY, category, Severity.CRITICAL, 1f, Source.NATIVE,
                mapOf("reason" to "writable+executable mapping of libdevcheck.so"),
            )
        }

        out
    }

    private fun signatureSha256(ctx: Context): List<String> = runCatching {
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signing = info.signingInfo ?: return emptyList()
        val certs = if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
        certs.orEmpty().map { sha256Hex(it.toByteArray()) }
    }.getOrDefault(emptyList())
}
