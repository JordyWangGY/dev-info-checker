package com.devcheck.detector

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.Collections
import kotlin.math.sqrt

/**
 * 传感器真实性：很多模拟器 / 改机"声称有"加速度计，但返回恒定值或零方差。
 * 这里短暂采样加速度计，检测是否静态 / 无物理噪声（真机即使静置也有微抖动）。
 *
 * 仅判定"是否静态"；从传感器微瑕疵生成"硬件指纹哈希"用于设备池比对属于服务端范畴，
 * 见 DETECTION_COVERAGE.md。
 */
internal class SensorDetector : Detector {
    override val id = "sensor"
    override val category = Category.EMULATOR
    override val timeoutMs: Long? = 2500L

    override suspend fun detect(ctx: DetectContext): List<Signal> {
        val sm = ctx.app.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return emptyList()
        // 缺失加速度计由 EmulatorDetector(no_sensors) 负责，这里只管"有但是假"
        val accel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) ?: return emptyList()

        val samples = sample(sm, accel, maxSamples = 50, windowMs = 800)
        if (samples.size < 5) {
            return listOf(
                Signal(
                    Signals.EMULATOR_SENSOR_STATIC, category, Severity.MEDIUM, 0.5f, Source.JAVA,
                    mapOf("reason" to "too_few_events", "count" to samples.size.toString()),
                ),
            )
        }
        val variance = magnitudeVariance(samples)
        return if (variance < 1e-6) {
            listOf(
                Signal(
                    Signals.EMULATOR_SENSOR_STATIC, category, Severity.HIGH, 0.7f, Source.JAVA,
                    mapOf("variance" to "%.3e".format(variance), "samples" to samples.size.toString()),
                ),
            )
        } else {
            emptyList()
        }
    }

    private suspend fun sample(sm: SensorManager, sensor: Sensor, maxSamples: Int, windowMs: Long): List<FloatArray> {
        val data = Collections.synchronizedList(ArrayList<FloatArray>())
        var listener: SensorEventListener? = null
        try {
            withTimeoutOrNull(windowMs) {
                suspendCancellableCoroutine<Unit> { cont ->
                    val l = object : SensorEventListener {
                        override fun onSensorChanged(e: SensorEvent) {
                            data.add(e.values.copyOf())
                            if (data.size >= maxSamples && cont.isActive) cont.resumeWith(Result.success(Unit))
                        }

                        override fun onAccuracyChanged(s: Sensor?, a: Int) {}
                    }
                    listener = l
                    sm.registerListener(l, sensor, SensorManager.SENSOR_DELAY_GAME)
                    cont.invokeOnCancellation { sm.unregisterListener(l) }
                }
            }
        } finally {
            listener?.let { sm.unregisterListener(it) }
        }
        return ArrayList(data)
    }

    private fun magnitudeVariance(samples: List<FloatArray>): Double {
        val mags = samples.mapNotNull { v ->
            if (v.size >= 3) sqrt((v[0] * v[0] + v[1] * v[1] + v[2] * v[2]).toDouble()) else null
        }
        if (mags.isEmpty()) return 0.0
        val mean = mags.average()
        return mags.sumOf { (it - mean) * (it - mean) } / mags.size
    }
}
