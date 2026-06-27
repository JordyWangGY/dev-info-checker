package com.devcheck.detector

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.telephony.TelephonyManager
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * WiFi BSSID / 基站信息采集（仅采集，群控聚类在服务端）。
 *
 * 这两项是"设备池/群控识别"的关键输入：N 个不同账号若周边 WiFi(BSSID) 列表或基站完全一致，
 * 说明在同一屋檐下 = 工作室。但**关联/聚类是服务端能力**（见 DETECTION_COVERAGE.md）。
 *
 * 需要宿主已申请并被授予 ACCESS_FINE_LOCATION；未授予则只上报"不可用"，不做风险加分。
 */
internal class RadioDetector : Detector {
    override val id = "radio"
    override val category = Category.FINGERPRINT

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()
        val granted = ctx.app.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) {
            out += Signal(
                Signals.FP_WIFI, category, Severity.INFO, 1f, Source.JAVA,
                mapOf("available" to "false", "reason" to "ACCESS_FINE_LOCATION not granted"),
            )
            return@withContext out
        }

        runCatching {
            val wm = ctx.app.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION") val bssid = wm.connectionInfo.bssid
            if (!bssid.isNullOrBlank() && bssid != "02:00:00:00:00:00") {
                out += Signal(Signals.FP_WIFI, category, Severity.INFO, 1f, Source.JAVA, mapOf("bssid" to bssid))
            }
        }

        runCatching {
            val tm = ctx.app.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            val cells = tm.allCellInfo
            out += Signal(
                Signals.FP_CELL, category, Severity.INFO, 1f, Source.JAVA,
                mapOf("count" to (cells?.size ?: 0).toString()),
            )
        }

        out
    }
}
