package com.devcheck.detector

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

internal class EmulatorDetector : Detector {
    override val id = "emulator"
    override val category = Category.EMULATOR

    private val qemuFiles = listOf(
        "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props",
        "/dev/socket/genyd", "/dev/socket/baseband_genyd", // Genymotion
    )

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()

        val hits = buildList {
            val fp = Build.FINGERPRINT
            if (fp.startsWith("generic") || fp.contains("vbox") || fp.contains("emulator") ||
                fp.contains("sdk_gphone") || fp.contains("unknown")
            ) add("fingerprint=$fp")
            if (Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK built for") ||
                Build.MODEL.contains("sdk_gphone")
            ) add("model=${Build.MODEL}")
            if (Build.MANUFACTURER.contains("Genymotion")) add("manufacturer=${Build.MANUFACTURER}")
            if (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) add("brand/device=generic")
            if (Build.PRODUCT.contains("sdk") || Build.PRODUCT.contains("vbox") ||
                Build.PRODUCT.contains("emulator") || Build.PRODUCT.contains("simulator")
            ) add("product=${Build.PRODUCT}")
            if (Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu") ||
                Build.HARDWARE.contains("vbox")
            ) add("hardware=${Build.HARDWARE}")
            if (Build.BOARD.equals("unknown", true)) add("board=unknown")
        }
        if (hits.isNotEmpty()) {
            val sev = if (hits.size >= 2) Severity.HIGH else Severity.MEDIUM
            out += Signal(
                Signals.EMULATOR_BUILD_PROPS, category, sev,
                minOf(1f, 0.5f + 0.15f * hits.size), Source.JAVA,
                mapOf("hits" to hits.joinToString()),
            )
        }

        val fileHits = qemuFiles.filter { ctx.native.pathExists(it) || File(it).exists() }
        if (fileHits.isNotEmpty()) {
            out += Signal(
                Signals.EMULATOR_FILES, category, Severity.HIGH, 0.9f, Source.JAVA,
                mapOf("files" to fileHits.joinToString()),
            )
        }

        // 原生 syscall(faccessat) 确认 QEMU 管道设备 → 阻断点（仅模拟器具备）
        if (ctx.native.isAvailable) {
            val pipes = listOf("/dev/qemu_pipe", "/dev/socket/qemud", "/dev/socket/genyd")
                .filter { ctx.native.pathExists(it) }
            if (pipes.isNotEmpty()) {
                out += Signal(
                    Signals.EMULATOR_QEMU_PIPE, category, Severity.CRITICAL, 1f, Source.NATIVE,
                    mapOf("pipes" to pipes.joinToString()),
                )
            }
        }

        if (Build.SUPPORTED_ABIS.any { it.startsWith("x86") }) {
            out += Signal(
                Signals.EMULATOR_CPU_ARCH, category, Severity.LOW, 0.4f, Source.JAVA,
                mapOf("abis" to Build.SUPPORTED_ABIS.joinToString()),
            )
        }

        val sm = ctx.app.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        if (sm != null) {
            val hasAccel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null
            val hasGyro = sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null
            if (!hasAccel || !hasGyro) {
                out += Signal(
                    Signals.EMULATOR_NO_SENSORS, category, Severity.MEDIUM, 0.6f, Source.JAVA,
                    mapOf("accelerometer" to hasAccel.toString(), "gyroscope" to hasGyro.toString()),
                )
            }
        }

        out
    }
}
