package com.devcheck.export

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.util.Log
import com.devcheck.DevCheck
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File

/**
 * 通过 adb 触发检测并导出结果(JSON)。
 *
 * **安全**：仅在「可调试(debuggable)」应用中生效——release 应用里为空操作，避免被滥用触发。
 *
 * 用法：
 * ```
 * adb shell am broadcast -n <包名>/com.devcheck.export.ExportReceiver
 * # 取回（任选其一）：
 * adb shell run-as <包名> cat files/devcheck-report.json
 * adb pull /sdcard/Android/data/<包名>/files/devcheck-report.json
 * adb logcat -s DevCheck:I        # JSON 在 DEVCHECK_REPORT_BEGIN/END 之间
 * ```
 */
class ExportReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val app = context.applicationContext
        if ((app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            Log.w(TAG, "export ignored: app is not debuggable")
            return
        }

        val pending = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                DevCheck.ensureInit(app)
                val json = DevCheck.evaluateJson()

                val internal = File(app.filesDir, FILE_NAME).apply { writeText(json) }
                val external = runCatching {
                    app.getExternalFilesDir(null)?.let { File(it, FILE_NAME).apply { writeText(json) } }
                }.getOrNull()

                Log.i(TAG, "report exported -> internal=${internal.absolutePath} external=${external?.absolutePath}")
                Log.i(TAG, "$MARK_BEGIN\n$json\n$MARK_END")
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
    }
}
