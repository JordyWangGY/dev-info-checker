package com.devcheck.detector

import com.devcheck.core.readSelfMaps
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** 多开 / 虚拟空间（VirtualApp / 平行空间 / 双开助手）检测。 */
internal class VirtualSpaceDetector : Detector {
    override val id = "vspace"
    override val category = Category.VSPACE

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()
        val pkg = ctx.app.packageName
        val dataDir = ctx.app.applicationInfo.dataDir ?: ""

        // 1) data 目录路径异常：正常应形如 /data/user/0/<pkg> 或 /data/data/<pkg>
        val pathSuspicious = dataDir.isNotEmpty() &&
            (!dataDir.contains(pkg) || dataDir.contains("/virtual") ||
                Regex("/data/(data|user/\\d+)/[^/]+/.+/$pkg").containsMatchIn(dataDir))
        if (pathSuspicious) {
            out += sig(Signals.VSPACE_DATA_PATH, Severity.MEDIUM, 0.6f, mapOf("dataDir" to dataDir, "pkg" to pkg))
        }

        // 2) /proc/self/maps 映射了其它包的 apk（被宿主在同进程加载的典型特征）
        val foreignApks = readSelfMaps()
            .filter { it.contains("base.apk") && (it.contains("/data/data/") || it.contains("/data/user/")) && !it.contains(pkg) }
            .map { it.substringAfterLast(' ') }
            .distinct()
        if (foreignApks.isNotEmpty()) {
            out += sig(
                Signals.VSPACE_FOREIGN_APK, Severity.MEDIUM, 0.6f,
                mapOf("count" to foreignApks.size.toString(), "sample" to foreignApks.first()),
            )
        }

        out
    }

    private fun sig(id: String, sev: Severity, conf: Float, ev: Map<String, String>) =
        Signal(id, category, sev, conf, Source.JAVA, ev)
}
