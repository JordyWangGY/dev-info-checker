package com.devcheck.detector

import android.annotation.SuppressLint
import android.os.Build
import android.provider.Settings
import com.devcheck.core.sha256Hex
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 设备指纹采集与自洽性。阶段一只产出 INFO 级指纹（不计分），
 * 作为阶段二服务端做去重 / 频次 / 关联风控的输入。
 */
internal class DeviceFingerprintDetector : Detector {
    override val id = "fingerprint"
    override val category = Category.FINGERPRINT

    @SuppressLint("HardwareIds")
    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val androidId = runCatching {
            Settings.Secure.getString(ctx.app.contentResolver, Settings.Secure.ANDROID_ID)
        }.getOrNull().orEmpty()

        val raw = listOf(
            Build.MANUFACTURER, Build.BRAND, Build.MODEL, Build.DEVICE,
            Build.BOARD, Build.HARDWARE, Build.FINGERPRINT, androidId,
        ).joinToString("|")
        val fp = sha256Hex(raw.toByteArray()).take(16)

        listOf(
            Signal(
                Signals.FP_STABLE_ID, category, Severity.INFO, 1f, Source.JAVA,
                mapOf(
                    "fp" to fp,
                    "android_id_present" to androidId.isNotEmpty().toString(),
                    "abis" to Build.SUPPORTED_ABIS.joinToString(),
                    "model" to "${Build.MANUFACTURER}/${Build.MODEL}",
                ),
            ),
        )
    }
}
