package com.devcheck.detector

import android.content.pm.ApplicationInfo
import android.os.Debug
import android.provider.Settings
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

internal class DebugDetector : Detector {
    override val id = "debug"
    override val category = Category.DEBUG

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()

        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            out += Signal(
                Signals.DEBUG_DEBUGGER, category, Severity.HIGH, 1f, Source.JAVA,
                mapOf("connected" to Debug.isDebuggerConnected().toString()),
            )
        }

        val debuggable = (ctx.app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (debuggable) {
            out += Signal(
                Signals.DEBUG_DEBUGGABLE, category, Severity.MEDIUM, 0.8f, Source.JAVA,
                mapOf("flag" to "FLAG_DEBUGGABLE"),
            )
        }

        val adb = runCatching {
            Settings.Global.getInt(ctx.app.contentResolver, Settings.Global.ADB_ENABLED, 0)
        }.getOrDefault(0)
        if (adb == 1) {
            out += Signal(
                Signals.DEBUG_ADB, category, Severity.LOW, 0.5f, Source.JAVA,
                mapOf("adb_enabled" to "1"),
            )
        }

        // TracerPid：优先原生（抗 hook），否则 Java 读 /proc/self/status
        val tracer = ctx.native.tracerPid().takeIf { it >= 0 } ?: javaTracerPid()
        if (tracer > 0) {
            out += Signal(
                Signals.DEBUG_TRACERPID, category, Severity.HIGH, 0.9f,
                if (ctx.native.isAvailable) Source.NATIVE else Source.JAVA,
                mapOf("tracer_pid" to tracer.toString()),
            )
        }

        out
    }

    private fun javaTracerPid(): Int = runCatching {
        File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
        }
    }.getOrDefault(0)
}
