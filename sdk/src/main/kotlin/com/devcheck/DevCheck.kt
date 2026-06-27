package com.devcheck

import android.content.Context
import com.devcheck.core.LocalRiskScorer
import com.devcheck.core.Orchestrator
import com.devcheck.detector.AttestDetector
import com.devcheck.detector.DebugDetector
import com.devcheck.detector.DetectContext
import com.devcheck.detector.Detector
import com.devcheck.detector.DeviceFingerprintDetector
import com.devcheck.detector.EmulatorDetector
import com.devcheck.detector.HookDetector
import com.devcheck.detector.NetworkDetector
import com.devcheck.detector.RootDetector
import com.devcheck.detector.TamperDetector
import com.devcheck.detector.VirtualSpaceDetector
import com.devcheck.nativebridge.NativeProbe
import com.devcheck.protocol.Category
import com.devcheck.protocol.RiskReport
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * SDK 公共入口。
 *
 * ```
 * DevCheck.init(context, DevCheckConfig())
 * val report = DevCheck.evaluate()   // 挂起；或用 callback 重载
 * ```
 */
object DevCheck {

    @Volatile private var config: DevCheckConfig? = null
    @Volatile private var appContext: Context? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** 阶段一启用的检测器集合（阶段一 1.1 起逐步补齐 Hook/VSpace/Tamper/Network/Fingerprint）。 */
    private val detectors: List<Detector> by lazy {
        listOf(
            EmulatorDetector(),
            RootDetector(),
            DebugDetector(),
            HookDetector(),
            VirtualSpaceDetector(),
            TamperDetector(),
            NetworkDetector(),
            DeviceFingerprintDetector(),
            AttestDetector(),
        )
    }

    fun init(context: Context, config: DevCheckConfig) {
        this.appContext = context.applicationContext
        this.config = config
    }

    suspend fun evaluate(): RiskReport = withContext(Dispatchers.Default) {
        val cfg = config ?: error("DevCheck.init() must be called before evaluate()")
        val ctx = appContext ?: error("DevCheck not initialized")
        val start = System.nanoTime()

        val signals = mutableListOf<Signal>()
        if (!NativeProbe.isAvailable) {
            signals += Signal(
                id = Signals.NATIVE_UNAVAILABLE,
                category = Category.RUNTIME,
                severity = Severity.INFO,
                source = Source.JAVA,
                evidence = mapOf("note" to "native core not loaded; running java-only checks"),
            )
        }
        // 穷尽式检测：所有 detector 并发跑完，命中阻断点不提前结束；
        // 阻断点的「硬覆盖」只发生在评分阶段，全部证据与全部阻断点都会保留在 report 中。
        signals += Orchestrator(detectors, cfg.perDetectorTimeoutMs)
            .run(DetectContext(ctx, cfg, NativeProbe))

        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        LocalRiskScorer.build(signals, elapsedMs, NativeProbe.isAvailable)
    }

    /** 回调重载；回调在后台线程触发，UI 更新请自行切主线程。 */
    fun evaluate(callback: (RiskReport) -> Unit) {
        scope.launch { callback(evaluate()) }
    }
}
