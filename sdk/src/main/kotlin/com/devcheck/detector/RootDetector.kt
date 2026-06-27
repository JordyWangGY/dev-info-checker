package com.devcheck.detector

import android.os.Build
import com.devcheck.core.Secrets
import com.devcheck.core.readMountInfo
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

internal class RootDetector : Detector {
    override val id = "root"
    override val category = Category.ROOT

    // 检测特征以 XOR+Base64 混淆存储（见 Secrets），避免被 strings/反编译直接 grep
    private val suPaths = Secrets.list(
        "dSkjKS4/N3U4MzR1KS8=", "dSkjKS4/N3UiODM0dSkv", "dSk4MzR1KS8=", "dSkvdTgzNHUpLw==",
        "dT47Ljt1NjU5OzZ1IjgzNHUpLw==", "dT47Ljt1NjU5OzZ1ODM0dSkv", "dSkjKS4/N3UpPnUiODM0dSkv",
        "dT47Ljt1NjU5OzZ1KS8=", "dSkjKS4/N3U4MzR1dD8iLnV0KS8=", "dSkjKS4/N3U7Kip1CS8qPygvKT8odDsqMQ==",
    )
    private val magiskPaths = Secrets.list(
        "dSk4MzR1dDc7PTMpMQ==", "dT47Ljt1Oz44dTc7PTMpMQ==", "dT47Ljt1Oz44dTc1Pi82Pyk=",
        "dTk7OTI/dXQ+Myk7ODY/BTc7PTMpMQ==", "dT4/LHV0Nzs9MykxdC80ODY1OTE=", "dT47Ljt1Oz44dTc7PTMpMXQ+OA==",
    )
    private val rootPackages = Secrets.list(
        "OTU3dC41KjA1MjQtL3Q3Oz0zKTE=", "Py90OTI7MzQ8Myg/dCkvKj8oKS8=",
        "OTU3dDE1LykyMzE+Ly4uO3QpLyo/KC8pPyg=", "OTU3dDQ1KTIvPDUvdDs0Pig1Mz50KS8=",
        "Nz90LT8zKTIvdDE/KDQ/Nikv", "Nz90ODc7InQ7KjsuOTI=", // me.bmax.apatch
    )

    // KernelSU / APatch 内核级提权特征路径（混淆存储）
    private val kernelSuPaths = Secrets.list(
        "dT47Ljt1Oz44dTEpLw==", "dT47Ljt1Oz44dTEpLz4=", "dT47Ljt1Oz44dTEpL3U3NT4vNj8p",
        "dT47Ljt1Oz44dTsq", "dT47Ljt1Oz44dTsqPg==", "dT47Ljt1Oz44dTsqdTc1Pi82Pyk=",
    )

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()

        if (Build.TAGS?.contains("test-keys") == true) {
            out += sig(Signals.ROOT_TEST_KEYS, Severity.MEDIUM, 0.6f, mapOf("tags" to Build.TAGS))
        }

        val suHits = suPaths.filter { exists(ctx, it) }
        if (suHits.isNotEmpty()) {
            out += sig(Signals.ROOT_SU_BINARY, Severity.HIGH, 0.9f, mapOf("paths" to suHits.joinToString()))
        }

        val magiskHits = magiskPaths.filter { exists(ctx, it) }
        if (magiskHits.isNotEmpty()) {
            out += sig(Signals.ROOT_MAGISK, Severity.HIGH, 0.9f, mapOf("paths" to magiskHits.joinToString()))
        }

        val ksuHits = kernelSuPaths.filter { exists(ctx, it) }
        if (ksuHits.isNotEmpty()) {
            out += sig(Signals.ROOT_KERNELSU, Severity.HIGH, 0.9f, mapOf("paths" to ksuHits.joinToString()))
        }

        val pathSu = (System.getenv("PATH") ?: "").split(":")
            .filter { it.isNotBlank() }
            .map { File(it, "su") }
            .filter { it.exists() }
        if (pathSu.isNotEmpty()) {
            out += sig(Signals.ROOT_SU_BINARY, Severity.HIGH, 0.85f, mapOf("path_su" to pathSu.joinToString()))
        }

        val pm = ctx.app.packageManager
        val installed = rootPackages.filter {
            runCatching { pm.getPackageInfo(it, 0); true }.getOrDefault(false)
        }
        if (installed.isNotEmpty()) {
            out += sig(Signals.ROOT_PACKAGES, Severity.MEDIUM, 0.7f, mapOf("packages" to installed.joinToString()))
        }

        val rwDirs = listOf("/system", "/system/bin", "/vendor", "/etc").filter { File(it).canWrite() }
        if (rwDirs.isNotEmpty()) {
            out += sig(Signals.ROOT_RW_SYSTEM, Severity.HIGH, 0.8f, mapOf("dirs" to rwDirs.joinToString()))
        }

        // 危险系统属性（原生读，抗 hook）
        if (ctx.native.isAvailable) {
            val bad = buildList {
                if (ctx.native.getProp("ro.secure") == "0") add("ro.secure=0")
                if (ctx.native.getProp("ro.debuggable") == "1") add("ro.debuggable=1")
                if (ctx.native.getProp("service.adb.root") == "1") add("service.adb.root=1")
            }
            if (bad.isNotEmpty()) out += sig(Signals.ROOT_DANGEROUS_PROPS, Severity.MEDIUM, 0.6f, mapOf("props" to bad.joinToString()))
        }

        // 挂载痕迹：magisk / KSU / APatch
        val mountHits = readMountInfo().filter { l ->
            val low = l.lowercase()
            listOf("magisk", "/data/adb", "ksu", "apatch").any { low.contains(it) }
        }
        if (mountHits.isNotEmpty()) {
            out += sig(Signals.ROOT_MOUNTS, Severity.HIGH, 0.7f, mapOf("count" to mountHits.size.toString(), "sample" to mountHits.first().take(180)))
        }

        out
    }

    private fun exists(ctx: DetectContext, path: String): Boolean =
        ctx.native.pathExists(path) || File(path).exists()

    private fun sig(id: String, sev: Severity, conf: Float, ev: Map<String, String>) =
        Signal(id, category, sev, conf, Source.JAVA, ev)
}
