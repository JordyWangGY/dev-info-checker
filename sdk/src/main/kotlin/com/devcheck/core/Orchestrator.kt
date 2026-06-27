package com.devcheck.core

import com.devcheck.detector.DetectContext
import com.devcheck.detector.Detector
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout

/**
 * 并发跑所有启用的 Detector，带每个 Detector 的超时。
 * 任一 Detector 超时 / 抛异常 → 记一条 fail-closed 信号（MEDIUM），而非静默通过。
 */
internal class Orchestrator(
    private val detectors: List<Detector>,
    private val timeoutMs: Long,
) {
    suspend fun run(ctx: DetectContext): List<Signal> = coroutineScope {
        detectors
            .filter { it.category in ctx.config.enabledCategories }
            .map { d ->
                async {
                    try {
                        withTimeout(d.timeoutMs ?: timeoutMs) { d.detect(ctx) }
                    } catch (e: TimeoutCancellationException) {
                        listOf(failClosed(d, "timeout"))
                    } catch (t: Throwable) {
                        listOf(failClosed(d, "${t.javaClass.simpleName}:${t.message ?: ""}"))
                    }
                }
            }
            .awaitAll()
            .flatten()
    }

    private fun failClosed(d: Detector, reason: String) = Signal(
        id = Signals.DETECTOR_ERROR,
        category = d.category,
        severity = Severity.MEDIUM,
        confidence = 1f,
        source = Source.JAVA,
        evidence = mapOf("detector" to d.id, "reason" to reason),
    )
}
