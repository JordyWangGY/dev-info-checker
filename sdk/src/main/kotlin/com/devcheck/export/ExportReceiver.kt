package com.devcheck.export

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.util.Log
import com.devcheck.DevCheck
import com.devcheck.protocol.toCompactJson
import com.devcheck.protocol.toJson
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File

/**
 * 通过 adb 触发检测并导出结果(JSON)。**debug 与 release 均可用。**
 *
 * release 非 debuggable、`run-as`/scoped-storage 取文件失效，故一律经 **logcat 分块**导出：
 * JSON 按 ~2KB 分块（规避 logcat 单条 ~4KB 截断），由 install.sh 从 `DEVCHECK_CHUNK` 行重组。
 * debug 包同时写内部/外部文件，便于 run-as/pull 直取完整文件。
 *
 * 用法：
 * ```
 * adb shell am broadcast -n <包名>/com.devcheck.export.ExportReceiver
 * adb logcat -s DevCheck:I -v raw   # 取 DEVCHECK_REPORT_BEGIN..END 间的 DEVCHECK_CHUNK 行重组
 * ```
 * 注：receiver 为 exported；宿主若不需要 adb 导出，应在自身 manifest 用 tools:node="remove" 移除。
 */
class ExportReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val app = context.applicationContext
        val debuggable = (app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

        val pending = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                DevCheck.ensureInit(app)
                val report = DevCheck.evaluate()

                // debug 包写文件（run-as/pull 可取完整美化文件）；release 无此权限，忽略失败。
                if (debuggable) {
                    val pretty = report.toJson()
                    runCatching { File(app.filesDir, FILE_NAME).writeText(pretty) }
                    runCatching { app.getExternalFilesDir(null)?.let { File(it, FILE_NAME).writeText(pretty) } }
                }

                // 主通道：logcat 分块（debug/release 通用）。用**紧凑单行 JSON**——每块恰好一行，
                // 规避 logcat 单条 ~4KB 截断 + 美化换行被拆行的问题。
                val compact = report.toCompactJson()
                Log.i(TAG, MARK_BEGIN)
                var i = 0
                compact.chunked(CHUNK).forEach { Log.i(TAG, "$CHUNK_TAG ${i++} $it") }
                Log.i(TAG, MARK_END)
            } catch (t: Throwable) {
                Log.e(TAG, "export failed: ${t.message}", t)
            } finally {
                pending.finish()
            }
        }
    }

    private companion object {
        const val TAG = "DevCheck"
        const val FILE_NAME = "devcheck-report.json"
        const val MARK_BEGIN = "DEVCHECK_REPORT_BEGIN"
        const val MARK_END = "DEVCHECK_REPORT_END"
        const val CHUNK_TAG = "DEVCHECK_CHUNK"
        const val CHUNK = 2000
    }
}
