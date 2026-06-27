package com.devcheck.detector

import com.devcheck.core.Secrets
import com.devcheck.core.readSelfMaps
import com.devcheck.core.readThreadNames
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/** Xposed / LSPosed / Frida / Substrate 等运行时注入检测（Java 层；原生强化见 1.2）。 */
internal class HookDetector : Detector {
    override val id = "hook"
    override val category = Category.HOOK

    // 检测特征以 XOR+Base64 混淆存储（见 Secrets）
    private val xposedClasses = Secrets.list(
        "Pj90KDU4LHQ7ND4oNTM+dCIqNSk/PnQCKjUpPz4YKDM+PT8=",
        "Pj90KDU4LHQ7ND4oNTM+dCIqNSk/PnQCKjUpPz4SPzYqPygp",
        "Pj90KDU4LHQ7ND4oNTM+dCIqNSk/PnQTAio1KT8+EjU1MRY1Oz4KOzkxOz0/",
    )
    private val mapsXposed = Secrets.list(
        "Iio1KT8+OCgzPj0/", "NjM4NikqPg==", "NikqOy45Mg==", "NjM4Pz4iKg==",
        "NjM4KDMoLw==", "KTs0PjI1NTE=", "NjM4LTI7Nj8=",
    )
    private val mapsFrida = Secrets.list(
        "PCgzPjs=", "PS83dzAp", "PCgzPjt3Oz0/NC4=", "PCgzPjt3PTs+PT8u", "NjM4PTs+PT8u", "NjM0MD85LjUo",
    )
    private val mapsSubstrate = Secrets.list("KS84KS4oOy4/", "NjM4KS84KS4oOy4/")
    private val fridaThreadNames = Secrets.list("PTc7MzQ=", "PS83dzApdzY1NSo=", "PT44Lyk=", "PCgzPjs=")
    private val fridaPorts = listOf(27042, 27043)

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()

        // 1) Xposed：尝试加载特征类
        val loaded = xposedClasses.filter { runCatching { Class.forName(it); true }.getOrDefault(false) }
        if (loaded.isNotEmpty()) {
            out += sig(Signals.HOOK_XPOSED, Severity.HIGH, 0.9f, mapOf("classes" to loaded.joinToString()))
        }

        // 2) Xposed：调用栈中的注入帧
        val xposedFrames = Throwable().stackTrace.filter {
            it.className.startsWith("de.robv.android.xposed") || it.className.contains("LSPosed", true)
        }
        if (xposedFrames.isNotEmpty()) {
            out += sig(Signals.HOOK_XPOSED, Severity.HIGH, 0.85f, mapOf("stack" to xposedFrames.first().className))
        }

        // 3) /proc/self/maps 扫描：原生可用→直接 syscall 读取(抗 hook)，来源 NATIVE(可触发阻断点)；
        //    否则 Java 兜底，来源 JAVA(仅计分，不阻断)
        val nativeAvail = ctx.native.isAvailable
        val mapLines = if (nativeAvail) ctx.native.suspiciousMaps().toList() else readSelfMaps()
        val mapSrc = if (nativeAvail) Source.NATIVE else Source.JAVA
        val lower = mapLines.map { it.lowercase() }
        mapsXposed.filter { n -> lower.any { it.contains(n) } }.let {
            if (it.isNotEmpty()) out += Signal(Signals.HOOK_XPOSED, category, Severity.HIGH, 0.9f, mapSrc, mapOf("maps" to it.joinToString()))
        }
        mapsFrida.filter { n -> lower.any { it.contains(n) } }.let {
            if (it.isNotEmpty()) out += Signal(Signals.HOOK_FRIDA_MAPS, category, Severity.HIGH, 0.9f, mapSrc, mapOf("maps" to it.joinToString()))
        }
        mapsSubstrate.filter { n -> lower.any { it.contains(n) } }.let {
            if (it.isNotEmpty()) out += Signal(Signals.HOOK_SUBSTRATE, category, Severity.HIGH, 0.85f, mapSrc, mapOf("maps" to it.joinToString()))
        }

        // 3b) inline hook：关键函数序言被改写为跳板（原生确认）→ 阻断点
        if (nativeAvail) {
            val hooked = ctx.native.inlineHookedFns()
            if (hooked.isNotEmpty()) {
                out += Signal(Signals.HOOK_INLINE, category, Severity.CRITICAL, 1f, Source.NATIVE, mapOf("fns" to hooked.joinToString()))
            }
        }

        // 4) Frida 默认端口
        val openPorts = fridaPorts.filter { portOpen("127.0.0.1", it, 120) }
        if (openPorts.isNotEmpty()) {
            out += sig(Signals.HOOK_FRIDA_PORT, Severity.MEDIUM, 0.7f, mapOf("ports" to openPorts.joinToString()))
        }

        // 5) Frida 特征线程名
        val threadHits = readThreadNames().filter { name -> fridaThreadNames.any { name.equals(it, true) } }
        if (threadHits.isNotEmpty()) {
            out += sig(Signals.HOOK_FRIDA_THREADS, Severity.MEDIUM, 0.6f, mapOf("threads" to threadHits.joinToString()))
        }

        out
    }

    private fun portOpen(host: String, port: Int, timeoutMs: Int): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(host, port), timeoutMs); true }
    }.getOrDefault(false)

    private fun sig(id: String, sev: Severity, conf: Float, ev: Map<String, String>) =
        Signal(id, category, sev, conf, Source.JAVA, ev)
}
