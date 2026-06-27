package com.devcheck.detector

import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 文件夹可达范围扫描 + 沙盒标记。
 *
 * 1. 枚举本 app 自有目录（内部 + 外部）的访问范围（读/写）；
 * 2. 对「当前 app 相关」目录，若路径不符合本应用规范（被多开 / 虚拟空间重定向到宿主目录）
 *    → **特别标记 ⚠沙盒**（vspace.sandbox）；
 * 3. 探测若干系统/共享目录的可读可列范围；若能列出他人 data 目录 → 非隔离环境（root/沙盒透传）。
 */
internal class StorageScanDetector : Detector {
    override val id = "storage"
    override val category = Category.VSPACE

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()
        val app = ctx.app
        val pkg = app.packageName
        // 规范内部路径：/data/data/<pkg> 或 /data/user/<n>/<pkg>
        val canonical = Regex("^/data/(data|user/\\d+)/" + Regex.escape(pkg) + "(/|$)")

        val appDirs = listOf(
            "dataDir" to (app.applicationInfo.dataDir ?: ""),
            "filesDir" to safe { app.filesDir.absolutePath },
            "cacheDir" to safe { app.cacheDir.absolutePath },
            "codeCacheDir" to safe { app.codeCacheDir.absolutePath },
            "noBackupDir" to safe { app.noBackupFilesDir.absolutePath },
            "obbDir" to safe { app.obbDir?.absolutePath },
            "externalFiles" to safe { app.getExternalFilesDir(null)?.absolutePath },
            "externalCache" to safe { app.externalCacheDir?.absolutePath },
        ).filter { it.second.isNotEmpty() }

        val sandboxDirs = mutableListOf<String>()
        val appLines = appDirs.joinToString("\n") { (name, path) ->
            val f = File(path)
            val perm = (if (f.canRead()) "r" else "-") + (if (f.canWrite()) "w" else "-")
            val internal = path.startsWith("/data/")
            val sandbox =
                if (internal) !canonical.containsMatchIn(if (path.endsWith("/")) path else "$path/")
                else !path.contains(pkg)
            if (sandbox) sandboxDirs += "$name=$path"
            "$name [$perm]${if (sandbox) " ⚠沙盒" else " (本应用)"} = $path"
        }

        // 系统/共享目录可达范围
        val probe = listOf(
            "/", "/data", "/data/data", "/data/app", "/sdcard", "/storage/emulated/0",
            "/system", "/vendor", "/proc", "/data/local/tmp",
        )
        val foreign = mutableListOf<String>()
        val reachLines = probe.joinToString("\n") { p ->
            val f = File(p)
            val r = f.canRead()
            val w = f.canWrite()
            val entries = if (r) runCatching { f.list()?.size ?: -1 }.getOrDefault(-1) else -1
            if ((p == "/data/data" || p == "/data/app") && entries > 0) foreign += "$p(entries=$entries)"
            "$p [${if (r) "r" else "-"}${if (w) "w" else "-"}]" + if (entries >= 0) " entries=$entries" else ""
        }

        out += Signal(
            Signals.STORAGE_SCOPE, Category.FINGERPRINT, Severity.INFO, 1f, Source.JAVA,
            mapOf("pkg" to pkg, "app_dirs" to appLines, "reachable" to reachLines),
        )

        // 特别标记：当前 app 相关目录被沙盒重定向
        if (sandboxDirs.isNotEmpty()) {
            out += Signal(
                Signals.VSPACE_SANDBOX, Category.VSPACE, Severity.HIGH, 0.8f, Source.JAVA,
                mapOf("sandbox_dirs" to sandboxDirs.joinToString(), "expected" to "/data/user/0/$pkg"),
            )
        }
        // 能列出他人 data 目录 = 非隔离（root 或沙盒透传）
        if (foreign.isNotEmpty()) {
            out += Signal(
                Signals.VSPACE_FOREIGN_DIR, Category.VSPACE, Severity.MEDIUM, 0.6f, Source.JAVA,
                mapOf("listable" to foreign.joinToString()),
            )
        }

        out
    }

    private inline fun safe(block: () -> String?): String = runCatching { block() }.getOrNull().orEmpty()
}
