package com.devcheck.detector

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
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
 * 定位相关采集：WiFi BSSID / 基站 / mock 定位（GPS 伪造）。
 *
 * 「特定场景才需要」：默认关闭，由 [com.devcheck.DevCheckConfig.collectLocation] 显式开启，
 * 且需宿主已被授予 ACCESS_FINE_LOCATION。任一不满足则跳过，不影响其它检测。
 * 群控聚类(同 WiFi/基站)在服务端完成；mock 定位是 GPS 伪造的强信号。
 */
internal class RadioDetector : Detector {
    override val id = "radio"
    override val category = Category.FINGERPRINT

    @SuppressLint("MissingPermission")
    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        if (!ctx.config.collectLocation) return@withContext emptyList()

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
            out += Signal(
                Signals.FP_CELL, category, Severity.INFO, 1f, Source.JAVA,
                mapOf("count" to (tm.allCellInfo?.size ?: 0).toString()),
            )
        }
        // mock 定位（GPS 伪造）：任一 provider 的最近定位标记为模拟
        runCatching {
            val lm = ctx.app.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            val mockProvider = lm?.getProviders(true).orEmpty()
                .firstOrNull { p -> lm?.getLastKnownLocation(p)?.isMock == true }
            if (mockProvider != null) {
                out += Signal(
                    Signals.ENV_MOCK_LOCATION, Category.ENVIRONMENT, Severity.HIGH, 0.8f, Source.JAVA,
                    mapOf("provider" to mockProvider),
                )
            }
        }
        out
    }
}
