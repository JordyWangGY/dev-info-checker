package com.devcheck.detector

import android.content.Context
import com.devcheck.DevCheckConfig
import com.devcheck.nativebridge.NativeProbe
import com.devcheck.protocol.Category
import com.devcheck.protocol.Signal

/** 传给每个 Detector 的运行时上下文。 */
class DetectContext(
    val app: Context,
    val config: DevCheckConfig,
    val native: NativeProbe,
    /** 本次检测的 nonce（服务端下发或本地兜底）；AttestDetector 用作 attestation challenge / PI nonce。 */
    val nonceB64: String = "",
    /** 阶段二证据出口：AttestDetector 把 PI 令牌原文 / attestation 证书链写入，供 DevCheck 组装上报包。 */
    val sink: EvidenceSink = EvidenceSink(),
)

/**
 * 阶段二上报数据的进程内出口。原始令牌 / 证书链**不进** [Signal] 的明文 evidence、不进日志，
 * 单独由此收集，再由 DevCheck 组装成 [com.devcheck.protocol.EvidenceBundle]（待加密上报）。
 */
class EvidenceSink {
    @Volatile var playIntegrityToken: String? = null
    @Volatile var attestationChainDerB64: List<String> = emptyList()
}

/**
 * 检测器接口。实现应：
 *  - 只采集证据、产出 [Signal]，不做最终裁决（裁决在 Scorer / 服务端）；
 *  - 在 IO 操作上切到 Dispatchers.IO；
 *  - 对自身异常保持「失败即风险」语义（由 Orchestrator 统一兜底）。
 */
interface Detector {
    val id: String
    val category: Category

    /** 单检测器超时覆盖（毫秒）；null 表示用全局 [DevCheckConfig.perDetectorTimeoutMs]。
     *  硬件背书等耗时操作可调大。 */
    val timeoutMs: Long? get() = null

    suspend fun detect(ctx: DetectContext): List<Signal>
}
