package com.devcheck.sample

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.util.Log
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.devcheck.DevCheck
import com.devcheck.DevCheckConfig
import com.devcheck.protocol.Blockers
import com.devcheck.protocol.RiskReport
import com.devcheck.protocol.Scoring
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Verdict
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : Activity() {

    private val ui = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var output: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        DevCheck.init(this, DevCheckConfig(debugLogging = true))

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 64, 40, 40)
        }
        root.addView(TextView(this).apply {
            text = "DevCheck — 环境检测（阶段一·纯客户端）"
            textSize = 20f
            setTypeface(typeface, Typeface.BOLD)
        })
        val btn = Button(this).apply { text = "运行检测" }
        root.addView(btn)
        output = TextView(this).apply {
            textSize = 13f
            typeface = Typeface.MONOSPACE
            movementMethod = ScrollingMovementMethod()
            setTextIsSelectable(true)
        }
        root.addView(ScrollView(this).apply {
            addView(output)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f,
            )
        })
        setContentView(root)

        btn.setOnClickListener { runCheck() }
        runCheck()
    }

    private fun runCheck() {
        output.text = "检测中…"
        ui.launch {
            val report = withContext(Dispatchers.Default) { DevCheck.evaluate() }
            render(report)
        }
    }

    private fun render(r: RiskReport) {
        val sb = StringBuilder()
        val badge = when (r.verdict) {
            Verdict.GENUINE -> "✅ 可信 GENUINE"
            Verdict.LOW_RISK -> "🟢 低风险 LOW_RISK"
            Verdict.SUSPICIOUS -> "🟠 可疑 SUSPICIOUS"
            Verdict.HIGH_RISK -> "🔴 高危 HIGH_RISK"
            Verdict.COMPROMISED -> "⛔ 不可信 COMPROMISED"
            Verdict.UNKNOWN -> "❔ 未知 UNKNOWN"
        }
        sb.append("════════════════════════════\n")
        sb.append("  $badge\n")
        sb.append("  风险分 ${r.score}/100\n")
        sb.append("════════════════════════════\n")
        sb.append("耗时 ${r.elapsedMs}ms · 原生核心 ${if (r.nativeAvailable) "✓" else "✗ (java-only)"}\n")

        if (r.blockingSignals.isNotEmpty()) {
            sb.append("\n⛔ 阻断点 ${r.blockingSignals.size} 项（命中即 100% 不可信）\n")
            for (b in r.blockingSignals) {
                sb.append("  ‼ ${b.id}  [${b.source}]\n")
                Blockers.of(b.id)?.let { sb.append("     ↳ ${it.reason}\n") }
            }
        }

        sb.append("\n分类得分\n")
        if (r.categoryScores.isEmpty()) {
            sb.append("  （全部干净）\n")
        } else {
            for ((cat, s) in r.categoryScores.entries.sortedByDescending { it.value }) {
                sb.append("  ${cat.name.padEnd(12)} $s\n")
            }
        }

        sb.append("\n信号明细 ${r.signals.size} 条\n")
        for ((cat, list) in r.signals.groupBy { it.category }) {
            sb.append("▸ $cat\n")
            for (s in list) {
                val blk = if (Scoring.isBlocker(s)) "  ‼阻断" else ""
                sb.append("   ${sevMark(s.severity)} ${s.id}  (${s.confidence}) [${s.source}]$blk\n")
                for ((k, v) in s.evidence) sb.append("        $k = $v\n")
            }
        }

        output.setTextColor(
            when (r.verdict) {
                Verdict.GENUINE -> Color.parseColor("#1B5E20")
                Verdict.LOW_RISK -> Color.parseColor("#33691E")
                Verdict.SUSPICIOUS -> Color.parseColor("#E65100")
                else -> Color.parseColor("#B71C1C")
            },
        )
        output.text = sb.toString()
        Log.i("DevCheck", "\n" + sb)
    }

    private fun sevMark(s: Severity): String = when (s) {
        Severity.CRITICAL -> "⛔"
        Severity.HIGH -> "🔴"
        Severity.MEDIUM -> "🟠"
        Severity.LOW -> "🟡"
        Severity.INFO -> "⚪"
    }
}
