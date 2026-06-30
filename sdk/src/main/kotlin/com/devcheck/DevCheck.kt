package com.devcheck

import android.content.Context
import com.devcheck.core.LocalRiskScorer
import com.devcheck.core.Orchestrator
import com.devcheck.detector.AttestDetector
import com.devcheck.detector.DebugDetector
import com.devcheck.detector.DetectContext
import com.devcheck.detector.Detector
import com.devcheck.detector.EvidenceSink
import com.devcheck.detector.DeviceFingerprintDetector
import com.devcheck.detector.EcosystemDetector
import com.devcheck.detector.EmulatorDetector
import com.devcheck.detector.EnvironmentDetector
import com.devcheck.detector.FileTimeDetector
import com.devcheck.detector.HookDetector
import com.devcheck.detector.NetworkDetector
import com.devcheck.detector.RadioDetector
import com.devcheck.detector.RootDetector
import com.devcheck.detector.SeLinuxDetector
import com.devcheck.detector.SensorDetector
import com.devcheck.detector.StorageScanDetector
import com.devcheck.detector.TamperDetector
import com.devcheck.detector.VirtualSpaceDetector
import com.devcheck.nativebridge.NativeProbe
import android.util.Base64
import com.devcheck.protocol.Category
import com.devcheck.protocol.EvidenceBundle
import com.devcheck.protocol.RiskReport
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import com.devcheck.protocol.toJson
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
    @Volatile private var lastBundle: EvidenceBundle? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** 阶段一启用的检测器集合（阶段一 1.1 起逐步补齐 Hook/VSpace/Tamper/Network/Fingerprint）。 */
    private val detectors: List<Detector> by lazy {
        listOf(
            EmulatorDetector(),
            SeLinuxDetector(),
            RootDetector(),
            DebugDetector(),
            HookDetector(),
            VirtualSpaceDetector(),
            StorageScanDetector(),
            TamperDetector(),
            NetworkDetector(),
            EcosystemDetector(),
            FileTimeDetector(),
            DeviceFingerprintDetector(),
            SensorDetector(),
            EnvironmentDetector(),
            RadioDetector(),
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
        // nonce：服务端优先（防重放），否则本地兜底。整次检测共用同一 nonce。
        val provided = runCatching { cfg.nonceProvider?.fetch() }.getOrNull()
        val nonceB64 = provided ?: localNonce()
        val nonceSource = if (provided != null) "server" else "local"
        val sink = EvidenceSink()

        // 穷尽式检测：所有 detector 并发跑完，命中阻断点不提前结束；
        // 阻断点的「硬覆盖」只发生在评分阶段，全部证据与全部阻断点都会保留在 report 中。
        signals += Orchestrator(detectors, cfg.perDetectorTimeoutMs)
            .run(DetectContext(ctx, cfg, NativeProbe, nonceB64, sink))

        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        val report = LocalRiskScorer.build(signals, elapsedMs, NativeProbe.isAvailable)

        // 阶段二上报包：信任锚（PI 令牌 / attestation 链）+ nonce + 本地报告，备好待加密上报。
        // 传输层（HTTP /v1/attest）属阶段二服务端就绪后再接，见 PHASE2_SERVER.md §5。
        lastBundle = EvidenceBundle(
            nonce = nonceB64,
            nonceSource = nonceSource,
            playIntegrityToken = sink.playIntegrityToken,
            keyAttestationChainDerB64 = sink.attestationChainDerB64,
            localReport = report,
        )
        report
    }

    /** 最近一次 evaluate 组装的阶段二上报包（含信任锚原始令牌/证书链）；未运行过则为 null。 */
    fun lastEvidenceBundle(): EvidenceBundle? = lastBundle

    private fun localNonce(): String = Base64.encodeToString(
        ByteArray(24).also { java.security.SecureRandom().nextBytes(it) },
        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
    )

    /** 回调重载；回调在后台线程触发，UI 更新请自行切主线程。 */
    fun evaluate(callback: (RiskReport) -> Unit) {
        scope.launch { callback(evaluate()) }
    }

    /** 运行检测并返回 JSON（用于 adb 导出 / 排查 / 上报）。 */
    suspend fun evaluateJson(): String = evaluate().toJson()

    /** 宿主未调用 init() 时用默认配置兜底（供 adb 导出等无宿主初始化场景）。已初始化则保留原配置。 */
    internal fun ensureInit(context: Context) {
        if (config == null) {
            appContext = context.applicationContext
            config = DevCheckConfig()
        }
    }
}
