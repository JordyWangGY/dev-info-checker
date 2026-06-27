package com.devcheck.detector

import android.content.ContentResolver
import android.provider.Settings
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 运行环境完整性（无需特殊权限）。这些信号多为"低风险/可疑"而非阻断点，
 * 主要价值是喂服务端做关联与一致性（见 DETECTION_COVERAGE.md）。
 *
 * mock 定位 / 自动化注入点击未在此实现：前者需定位采样或 AppOps、后者需宿主在 View 层
 * 把 MotionEvent 交给 SDK —— 均标注在 DETECTION_COVERAGE.md。
 */
internal class EnvironmentDetector : Detector {
    override val id = "environment"
    override val category = Category.ENVIRONMENT

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()
        val cr = ctx.app.contentResolver

        if (globalInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED) == 1) {
            out += Signal(Signals.ENV_DEVELOPER_OPTIONS, category, Severity.LOW, 0.3f, Source.JAVA, emptyMap())
        }

        // 无线调试（ADB over WiFi）
        if (globalInt(cr, "adb_wifi_enabled") == 1) {
            out += Signal(Signals.ENV_ADB_WIFI, category, Severity.MEDIUM, 0.5f, Source.JAVA, emptyMap())
        }

        // 已启用的无障碍服务（自动化/群控常滥用；正常用户也用 → LOW）
        val a11y = runCatching {
            Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        }.getOrNull().orEmpty()
        if (a11y.isNotBlank()) {
            val count = a11y.split(":").count { it.isNotBlank() }
            out += Signal(
                Signals.ENV_ACCESSIBILITY, category, Severity.LOW, 0.3f, Source.JAVA,
                mapOf("count" to count.toString()),
            )
        }

        out
    }

    private fun globalInt(cr: ContentResolver, key: String): Int =
        runCatching { Settings.Global.getInt(cr, key, 0) }.getOrDefault(0)
}
