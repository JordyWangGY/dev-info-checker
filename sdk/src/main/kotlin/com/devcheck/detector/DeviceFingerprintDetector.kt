package com.devcheck.detector

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.content.Context
import android.media.MediaDrm
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
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

/**
 * 设备指纹 / 全面属性采集。
 *
 * 设计取向（来自攻防推演）：客户端做"**宽而可信**的属性采集"，把内部自洽 / 群体基线 /
 * 设备池一致性 / 去重 / velocity 的判定交给**服务端**（见 DETECTION_COVERAGE.md）。
 * 这里只采集、不下结论（除少数本地即可判定的强冲突，如 x86 ABI 已在 EmulatorDetector）。
 *
 * 已按用户要求**排除**："读取厂商生态软件做型号一致性""文件创建时间指纹"。
 */
internal class DeviceFingerprintDetector : Detector {
    override val id = "fingerprint"
    override val category = Category.FINGERPRINT

    @SuppressLint("HardwareIds")
    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()
        val androidId = runCatching {
            Settings.Secure.getString(ctx.app.contentResolver, Settings.Secure.ANDROID_ID)
        }.getOrNull().orEmpty()

        val raw = listOf(
            Build.MANUFACTURER, Build.BRAND, Build.MODEL, Build.DEVICE,
            Build.BOARD, Build.HARDWARE, Build.FINGERPRINT, androidId,
        ).joinToString("|")
        val fp = sha256Hex(raw.toByteArray()).take(16)

        val dm = ctx.app.resources.displayMetrics
        val am = ctx.app.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val mem = ActivityManager.MemoryInfo().also { am?.getMemoryInfo(it) }

        val attrs = linkedMapOf(
            "fp" to fp,
            "manufacturer" to Build.MANUFACTURER,
            "model" to Build.MODEL,
            "device" to Build.DEVICE,
            "board" to Build.BOARD,
            "hardware" to Build.HARDWARE,
            "soc" to "${Build.SOC_MANUFACTURER}/${Build.SOC_MODEL}",
            "abis" to Build.SUPPORTED_ABIS.joinToString(","),
            "cores" to Runtime.getRuntime().availableProcessors().toString(),
            "ram_mb" to (mem.totalMem / (1024 * 1024)).toString(),
            "screen" to "${dm.widthPixels}x${dm.heightPixels}@${dm.densityDpi}",
            "kernel" to (System.getProperty("os.version") ?: ""),
            "locale" to Locale.getDefault().toString(),
            "timezone" to TimeZone.getDefault().id,
            "android" to "${Build.VERSION.RELEASE}/${Build.VERSION.SDK_INT}",
            "android_id_present" to androidId.isNotEmpty().toString(),
        )
        out += Signal(Signals.FP_ATTRIBUTES, category, Severity.INFO, 1f, Source.JAVA, attrs)

        // Widevine DRM 安全级别（L1/L3）——"旗舰机型却只有 L3"之类的冲突由服务端结合机型库判定
        widevineLevel()?.let {
            out += Signal(
                Signals.FP_WIDEVINE, category, Severity.INFO, 1f, Source.HARDWARE,
                mapOf("securityLevel" to it),
            )
        }

        out
    }

    private fun widevineLevel(): String? = runCatching {
        val drm = MediaDrm(UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"))
        val level = drm.getPropertyString("securityLevel")
        drm.close()
        level
    }.getOrNull()
}
