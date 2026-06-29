package com.devcheck.detector

import android.os.Build
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 文件创建时间 / 时间戳异常：发现时钟篡改、克隆镜像、新构建的模拟器镜像。
 *
 * **仅计分、非阻断点**：时钟可被合法更改（NTP / 时区 / 用户调整），OEM 的 Build.TIME 偶有异常，
 * 故全部 conf<1 + 24h SLACK 容错，最坏只到 SUSPICIOUS。真实创建时间(crtime)经 native statx 采集。
 */
internal class FileTimeDetector : Detector {
    override val id = "filetime"
    override val category = Category.TAMPER

    // 仅 <queries> 白名单内的系统包可见、可读 firstInstallTime（无 QUERY_ALL_PACKAGES → 不能全量扫描）。
    // 取样覆盖美/欧/中主流品牌的代表包，提升「批量装机时间雷同」聚类的命中面。
    private val systemPackages = listOf(
        "com.google.android.gms", "com.android.vending", "com.google.android.gsf",
        "com.google.android.googlequicksearchbox", "com.google.android.apps.wellbeing",
        "com.sec.android.app.launcher", "com.google.android.apps.nexuslauncher",
        "com.motorola.launcher3", "com.oneplus.launcher", "com.nothing.launcher", "com.sonymobile.home",
        "com.miui.home", "com.android.thememanager", "com.heytap.market", "com.bbk.appstore",
        "com.huawei.android.launcher",
    )

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()
        val pm = ctx.app.packageManager
        val now = System.currentTimeMillis()
        val slack = 24L * 60 * 60 * 1000  // 24h：吸收 NTP / 时区抖动
        val floor2015 = 1_420_070_400_000L // 2015-01-01，Build.TIME 合理下限（防 OEM 置 0）

        // 1) 本 App 安装时间早于系统编译时间 = 真机不可能（克隆/预制镜像，或时钟回拨）
        val firstInstall = runCatching {
            pm.getPackageInfo(ctx.app.packageName, 0).firstInstallTime
        }.getOrDefault(0L)
        val buildTime = Build.TIME
        if (firstInstall > 0 && buildTime > floor2015 && firstInstall < buildTime - slack) {
            out += sig(
                Signals.FILETIME_INSTALL_BEFORE_BUILD, Severity.HIGH, 0.7f,
                mapOf(
                    "first_install" to firstInstall.toString(),
                    "build_time" to buildTime.toString(),
                    "delta_ms" to (buildTime - firstInstall).toString(),
                ),
            )
        }

        // 2) 多个系统包安装时间精确到秒雷同 = 一次性批量装机镜像
        val installSecs = systemPackages.mapNotNull { p ->
            runCatching { pm.getPackageInfo(p, 0).firstInstallTime / 1000 }.getOrNull()
        }.filter { it > 0 }
        val cluster = installSecs.groupingBy { it }.eachCount().maxByOrNull { it.value }
        if (cluster != null && cluster.value >= 5) {
            out += sig(
                Signals.FILETIME_UNIFORM_INSTALL, Severity.MEDIUM, 0.5f,
                mapOf(
                    "cluster_size" to cluster.value.toString(),
                    "epoch_sec" to cluster.key.toString(),
                    "sampled" to installSecs.size.toString(),
                ),
            )
        }

        // 3) 关键文件 mtime 在未来（超出 SLACK）= 时钟篡改
        val apkPath = ctx.app.applicationInfo.sourceDir
        val futureFiles = listOf(apkPath, ctx.app.filesDir.absolutePath)
            .mapNotNull { path -> runCatching { File(path).lastModified() }.getOrNull()?.let { path to it } }
            .filter { it.second > now + slack }
        if (futureFiles.isNotEmpty()) {
            out += sig(
                Signals.FILETIME_FUTURE_FILE, Severity.MEDIUM, 0.5f,
                mapOf(
                    "files" to futureFiles.joinToString { "${it.first}=${it.second}" },
                    "now" to now.toString(),
                ),
            )
        }

        // 4) 采集：APK / data 目录真实创建时间(statx btime)，不可用回落 mtime（INFO，0 分）
        val dataDir = ctx.app.applicationInfo.dataDir ?: ctx.app.filesDir.absolutePath
        val apkCr = ctx.native.crtime(apkPath)
        val dataCr = ctx.native.crtime(dataDir)
        val usedStatx = apkCr > 0 || dataCr > 0
        out += Signal(
            Signals.FILETIME_CRTIME, Category.FINGERPRINT, Severity.INFO, 1f,
            if (usedStatx) Source.NATIVE else Source.JAVA,
            mapOf(
                "apk_crtime" to (if (apkCr > 0) apkCr else File(apkPath).lastModified()).toString(),
                "data_crtime" to (if (dataCr > 0) dataCr else File(dataDir).lastModified()).toString(),
                "apk_mtime" to File(apkPath).lastModified().toString(),
                "source" to if (usedStatx) "statx" else "mtime",
            ),
        )

        out
    }

    private fun sig(id: String, sev: Severity, conf: Float, ev: Map<String, String>) =
        Signal(id, Category.TAMPER, sev, conf, Source.JAVA, ev)
}
