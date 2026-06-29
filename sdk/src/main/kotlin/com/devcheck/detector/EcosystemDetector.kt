package com.devcheck.detector

import android.content.pm.PackageManager
import android.os.Build
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 系统生态软件一致性：真机品牌 X 必然预装一组 OEM 系统包 + GMS；模拟器 / 伪造 Build.BRAND 的
 * 设备缺这套生态。检测「声称品牌 X 却没有 X 的任一特征系统包」。
 *
 * **仅计分、非阻断点**：定制 ROM / 无谷歌服务真机（LineageOS、国行）会合法缺包，故 conf<1、
 * 走加权评分；最终裁决交服务端结合机型库 + 地区(SIM 国家)复核（见 DETECTION_COVERAGE.md）。
 *
 * 注：探测的包名均为**公开信息**，且已在 AndroidManifest 的 `<queries>` 明文声明（API 30+ 可见性所需），
 * 故这里不像 RootDetector 那样用 Secrets 混淆——混淆对已在清单暴露的包名无意义。
 */
internal class EcosystemDetector : Detector {
    override val id = "ecosystem"
    override val category = Category.EMULATOR

    // 厂商 token（对 Build.BRAND/MANUFACTURER 小写做包含匹配）→ 特征系统包列表。
    // 排序按**美国 / 欧洲**市场主流度（三星、Pixel、摩托罗拉、OnePlus… 在前），中国品牌随后。
    // 仅收录有**明确特有生态包**的品牌；近原生 brand（如 Nokia/HMD、Fairphone）不设 token，
    // 交给 GMS 基线判定，避免误报。新增匹配包须同步加入 AndroidManifest 的 <queries>。
    private val vendorPackages: List<Pair<List<String>, List<String>>> = listOf(
        // —— 美国 / 欧洲主流 ——
        listOf("samsung") to listOf(
            "com.sec.android.app.launcher", "com.samsung.android.app.galaxyfinder",
            "com.samsung.android.messaging", "com.sec.android.daemonapp", "com.samsung.android.bixby.agent",
        ),
        listOf("google", "pixel") to listOf(
            "com.google.android.apps.nexuslauncher", "com.google.android.googlequicksearchbox",
            "com.google.android.apps.wellbeing", "com.google.android.apps.turbo", "com.google.android.as",
        ),
        listOf("motorola", "moto", "lenovo") to listOf(
            "com.motorola.launcher3", "com.motorola.ccc.ota", "com.motorola.motodisplay", "com.motorola.help",
        ),
        listOf("oneplus") to listOf(
            "com.oneplus.launcher", "net.oneplus.launcher", "com.oneplus.security",
        ),
        listOf("nothing") to listOf(
            "com.nothing.launcher", "com.nothing.thirdparty",
        ),
        listOf("sony", "xperia") to listOf(
            "com.sonymobile.home", "com.sonyericsson.home", "com.sonymobile.android.dialer",
        ),
        // —— 中国主流（欧洲也有份额）——
        listOf("xiaomi", "redmi", "poco") to listOf(
            "com.miui.home", "com.miui.securitycenter", "com.xiaomi.market",
            "com.miui.cleanmaster", "com.android.thememanager",
        ),
        listOf("oppo", "realme") to listOf(
            "com.heytap.market", "com.coloros.safecenter", "com.oppo.launcher", "com.heytap.themestore",
        ),
        listOf("vivo", "iqoo") to listOf(
            "com.bbk.appstore", "com.vivo.assistant", "com.vivo.upslide",
        ),
        listOf("huawei", "honor") to listOf(
            "com.huawei.android.launcher", "com.huawei.appmarket", "com.huawei.systemmanager", "com.hihonor.id",
        ),
    )

    private val gmsPackages = listOf(
        "com.google.android.gms", "com.android.vending", "com.google.android.gsf",
    )

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()
        val pm = ctx.app.packageManager

        val brand = "${Build.BRAND} ${Build.MANUFACTURER}".lowercase()
        val matched = vendorPackages.firstOrNull { (tokens, _) -> tokens.any { brand.contains(it) } }
        val vendorToken = matched?.first?.first() ?: "unknown"

        // GMS 基线：弱信号（无谷歌真机合法存在）
        val gmsPresent = gmsPackages.filter { isInstalled(pm, it) }
        if (gmsPresent.isEmpty()) {
            out += Signal(
                Signals.ECOSYSTEM_NO_GMS, Category.EMULATOR, Severity.MEDIUM, 0.5f, Source.JAVA,
                mapOf("checked" to gmsPackages.joinToString(), "present" to "none"),
            )
        }

        // 品牌生态一致性：声称品牌却零特征包 → 强烈的伪造/模拟器迹象
        val vendorPresent = matched?.second?.filter { isInstalled(pm, it) }.orEmpty()
        if (matched != null && vendorPresent.isEmpty()) {
            out += Signal(
                Signals.ECOSYSTEM_BRAND_MISMATCH, Category.EMULATOR, Severity.HIGH, 0.7f, Source.JAVA,
                mapOf(
                    "brand" to Build.BRAND, "manufacturer" to Build.MANUFACTURER,
                    "vendor" to vendorToken,
                    "expected" to matched.second.joinToString(), "present" to "0",
                ),
            )
        }

        // 采集：白名单命中清单（INFO，0 分），喂服务端一致性判定
        out += Signal(
            Signals.ECOSYSTEM_INVENTORY, Category.FINGERPRINT, Severity.INFO, 1f, Source.JAVA,
            mapOf(
                "claimed_vendor" to vendorToken,
                "vendor_present" to "${vendorPresent.size}/${matched?.second?.size ?: 0}",
                "gms_present" to gmsPresent.isNotEmpty().toString(),
                "matched_pkgs" to (vendorPresent + gmsPresent).joinToString(),
            ),
        )

        out
    }

    private fun isInstalled(pm: PackageManager, pkg: String): Boolean =
        runCatching { pm.getPackageInfo(pkg, 0); true }.getOrDefault(false)
}
