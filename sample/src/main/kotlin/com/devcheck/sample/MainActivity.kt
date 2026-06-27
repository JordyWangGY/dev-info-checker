package com.devcheck.sample

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.devcheck.DevCheck
import com.devcheck.DevCheckConfig
import com.devcheck.protocol.Blockers
import com.devcheck.protocol.Catalog
import com.devcheck.protocol.RiskReport
import com.devcheck.protocol.Scoring
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Verdict
import com.devcheck.protocol.toJson
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.tabs.TabLayout
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {

    private val ui = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private lateinit var tabs: TabLayout
    private lateinit var content: LinearLayout
    private var report: RiskReport? = null

    private val sub = Color.parseColor("#607D8B")
    private val ink = Color.parseColor("#37474F")
    private val green = Color.parseColor("#2E7D32")
    private val red = Color.parseColor("#B71C1C")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DevCheck.init(this, DevCheckConfig(debugLogging = true, collectLocation = true))

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#ECEFF1"))
        }

        // 顶部导航 = Tabs
        tabs = TabLayout(this).apply {
            tabMode = TabLayout.MODE_SCROLLABLE
            setBackgroundColor(Color.WHITE)
            listOf("总结", "打分", "阻断点", "检测点").forEach { addTab(newTab().setText(it)) }
            addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
                override fun onTabSelected(tab: TabLayout.Tab) = report?.let { renderTab(tab.position, it) } ?: Unit
                override fun onTabUnselected(tab: TabLayout.Tab) {}
                override fun onTabReselected(tab: TabLayout.Tab) {}
            })
        }
        root.addView(tabs)

        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(12), dp(14), dp(10)) }
        root.addView(ScrollView(this).apply {
            isFillViewport = true
            addView(content)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f)
        })

        setContentView(root)
        maybeRequestLocation()
        runCheck()
    }

    private fun maybeRequestLocation() {
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION),
                REQ_LOCATION,
            )
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_LOCATION) runCheck() // 授权后重跑，纳入定位相关检测
    }

    private fun runCheck() {
        content.removeAllViews()
        content.addView(simpleCard(sub, "检测中…", null))
        ui.launch {
            val r = withContext(Dispatchers.Default) { DevCheck.evaluate() }
            report = r
            logSummary(r)
            tabs.getTabAt(1)?.text = "打分 ${r.score}"
            tabs.getTabAt(2)?.text = "阻断点 ${r.blockingSignals.size}"
            tabs.getTabAt(3)?.text = "检测点 ${Catalog.ALL.size}"
            renderTab(tabs.selectedTabPosition.coerceAtLeast(0), r)
        }
    }

    private fun renderTab(i: Int, r: RiskReport) {
        content.removeAllViews()
        when (i) {
            0 -> renderSummary(r)
            1 -> renderScore(r)
            2 -> renderBlockers(r)
            else -> renderDetail(r)
        }
    }

    // ---------- Tab 0: 总结（含重新检测按钮）----------

    private fun renderSummary(r: RiskReport) {
        val (label, color) = verdictStyle(r.verdict)
        val (card, inner) = newCard()
        card.setCardBackgroundColor(withAlpha(color, 0x18))
        card.strokeColor = color
        card.strokeWidth = dp(2)
        inner.addView(TextView(this).apply {
            text = label; textSize = 22f; setTypeface(typeface, Typeface.BOLD); setTextColor(color)
        })
        inner.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(8), 0, dp(6))
            addView(stat("风险分", "${r.score}/100", ink))
            addView(stat("阻断点", "${r.blockingSignals.size}", if (r.blockingSignals.isEmpty()) green else red))
            addView(stat("命中信号", "${r.signals.count { it.severity != Severity.INFO }}", ink))
        })
        inner.addView(progress(r.score, 100, color))
        inner.addView(TextView(this).apply {
            text = "风险分越低越好（0=干净）· 命中阻断点即判不可信\n" +
                "耗时 ${r.elapsedMs}ms · 原生核心 ${if (r.nativeAvailable) "✓" else "✗"} · 检测点 ${Catalog.ALL.size}"
            textSize = 12f; setTextColor(sub); setPadding(0, dp(8), 0, 0)
        })
        content.addView(card)

        // 复制 / 导出：同一行，放在「重新检测」上方
        content.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) }
            addView(Button(this@MainActivity).apply {
                text = "复制"
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { rightMargin = dp(4) }
                setOnClickListener { copyJson() }
            })
            addView(Button(this@MainActivity).apply {
                text = "导出"
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { leftMargin = dp(4) }
                setOnClickListener { exportJson() }
            })
        })

        // 重新检测按钮：放在总结下方
        content.addView(Button(this).apply {
            text = "重新检测"
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(4) }
            setOnClickListener { runCheck() }
        })
        content.addView(hint("结论为本地参考；权威裁决见阶段二服务端。点上方页签查看打分 / 阻断点 / 全部检测点。"))
    }

    // ---------- Tab 1: 打分 ----------

    private fun renderScore(r: RiskReport) {
        val (label, color) = verdictStyle(r.verdict)
        content.addView(
            simpleCard(
                color, "风险分 ${r.score}/100　（越低越好，0=干净）",
                "裁决：$label\n" +
                    "算法：风险 = Σ 各类(命中权重 × 置信)，单类封顶 $CATEGORY_CAP、总分封顶 100。\n" +
                    "权重：INFO 0 · LOW 5 · MEDIUM 15 · HIGH 35 · CRITICAL 60。\n" +
                    "「通过/已采集」不加分；命中阻断点 → 直接判 COMPROMISED（不计入分数）。",
            ),
        )

        val scored = r.signals.filterNot { Scoring.isBlocker(it) || it.severity == Severity.INFO }
        if (scored.isEmpty()) {
            content.addView(simpleCard(green, "计分项 0", "没有可计分的命中信号，风险分 = 0"))
        } else {
            val byCat = scored.groupBy { it.category }
                .map { (c, list) ->
                    val subtotal = minOf(
                        CATEGORY_CAP,
                        list.sumOf { (Scoring.weight(it.severity) * it.confidence).toDouble() }.toInt(),
                    )
                    Triple(c, list, subtotal)
                }
                .sortedByDescending { it.third }
            for ((cat, list, subtotal) in byCat) {
                val c = scoreColor(subtotal)
                val inner = titledCard(c, "${cat.name}　小计 $subtotal / $CATEGORY_CAP")
                inner.addView(progress(subtotal, CATEGORY_CAP, c))
                for (s in list.sortedByDescending { Scoring.weight(it.severity) }) {
                    val pts = Scoring.weight(s.severity) * s.confidence
                    inner.addView(TextView(this).apply {
                        text = "  ${s.id}　${s.severity}×${s.confidence} = +${"%.1f".format(pts)}"
                        textSize = 12f; typeface = Typeface.MONOSPACE; setTextColor(ink); setPadding(0, dp(5), 0, 0)
                    })
                }
            }
        }

        if (r.blockingSignals.isNotEmpty()) {
            content.addView(
                simpleCard(
                    red, "阻断点 ${r.blockingSignals.size}（不计入分数，直接判不可信）",
                    r.blockingSignals.joinToString("\n") { "‼ ${it.id}" },
                ),
            )
        }
    }

    // ---------- Tab 2: 阻断点 ----------

    private fun renderBlockers(r: RiskReport) {
        if (r.blockingSignals.isEmpty()) {
            content.addView(simpleCard(green, "✅ 无阻断点", "未发现 100% 不可信的决定性证据"))
            return
        }
        content.addView(hint("命中即判定环境 100% 不可信（与分数无关）"))
        for (b in r.blockingSignals) {
            val body = buildString {
                append("[${b.source}] ${b.severity}\n")
                Blockers.of(b.id)?.let { append(it.reason).append('\n') }
                for ((k, v) in b.evidence) append("  $k = $v\n")
            }.trimEnd()
            content.addView(simpleCard(red, "‼ ${b.id}", body))
        }
    }

    // ---------- Tab 3: 检测点（全部检测项，含未命中）----------

    private fun renderDetail(r: RiskReport) {
        content.addView(hint("共 ${Catalog.ALL.size} 个客户端检测点　✅通过　⚪已采集　🟠/🔴/⛔命中"))
        for ((cat, points) in Catalog.ALL.groupBy { it.category }) {
            val hitInCat = points.count { p -> r.signals.any { it.id == p.id && it.severity != Severity.INFO } || r.blockingSignals.any { it.id == p.id } }
            val inner = titledCard(if (hitInCat > 0) red else ink, "▸ ${cat.name}　($hitInCat/${points.size} 命中)")
            for (p in points) {
                val sigs = r.signals.filter { it.id == p.id }
                val isBlock = r.blockingSignals.any { it.id == p.id }
                val (icon, color) = when {
                    isBlock -> "⛔" to red
                    sigs.isEmpty() -> "✅" to green
                    sigs.all { it.severity == Severity.INFO } -> "⚪" to sub
                    else -> sevMark(sigs.maxBy { it.severity.ordinal }.severity) to severityColor(sigs.maxBy { it.severity.ordinal }.severity)
                }
                inner.addView(TextView(this).apply {
                    text = "$icon ${p.desc}"
                    textSize = 14f; setTextColor(color); setPadding(0, dp(7), 0, 0)
                })
                inner.addView(TextView(this).apply {
                    text = "    ${p.id}"; textSize = 11f; typeface = Typeface.MONOSPACE; setTextColor(sub)
                })
                for (s in sigs) for ((k, v) in s.evidence) inner.addView(TextView(this).apply {
                    text = "      $k = $v"; textSize = 11f; typeface = Typeface.MONOSPACE; setTextColor(Color.parseColor("#90A4AE"))
                })
            }
        }
    }

    // ---------- Material card helpers ----------

    private fun newCard(): Pair<MaterialCardView, LinearLayout> {
        val card = MaterialCardView(this).apply {
            radius = dp(14).toFloat(); cardElevation = dp(1).toFloat()
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(8) }
        }
        val inner = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(14), dp(16), dp(14)) }
        card.addView(inner)
        return card to inner
    }

    private fun titledCard(accent: Int, title: String): LinearLayout {
        val (card, inner) = newCard()
        inner.addView(TextView(this).apply { text = title; textSize = 15f; setTypeface(typeface, Typeface.BOLD); setTextColor(accent) })
        content.addView(card)
        return inner
    }

    private fun simpleCard(accent: Int, title: String, body: String?): View {
        val (card, inner) = newCard()
        inner.addView(TextView(this).apply { text = title; textSize = 15f; setTypeface(typeface, Typeface.BOLD); setTextColor(accent) })
        if (!body.isNullOrEmpty()) inner.addView(TextView(this).apply {
            text = body; textSize = 13f; typeface = Typeface.MONOSPACE; setTextColor(Color.parseColor("#455A64")); setPadding(0, dp(6), 0, 0)
        })
        return card
    }

    private fun hint(text: String): View = TextView(this).apply {
        this.text = text; textSize = 12f; setTextColor(sub); setPadding(dp(4), dp(8), dp(4), dp(4))
    }

    private fun stat(label: String, value: String, color: Int): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
        addView(TextView(this@MainActivity).apply { text = value; textSize = 20f; setTypeface(typeface, Typeface.BOLD); setTextColor(color) })
        addView(TextView(this@MainActivity).apply { text = label; textSize = 11f; setTextColor(sub) })
    }

    private fun progress(value: Int, max: Int, color: Int): View = LinearProgressIndicator(this).apply {
        this.max = 100
        trackThickness = dp(8)
        trackCornerRadius = dp(4)
        setIndicatorColor(color)
        setProgressCompat((value * 100 / max).coerceIn(0, 100), false)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(2) }
    }

    // ---------- misc ----------

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
    private fun withAlpha(color: Int, alpha: Int) = (color and 0x00FFFFFF) or (alpha shl 24)

    private fun verdictStyle(v: Verdict): Pair<String, Int> = when (v) {
        Verdict.GENUINE -> "✅ 可信 GENUINE" to green
        Verdict.LOW_RISK -> "🟢 低风险 LOW_RISK" to Color.parseColor("#558B2F")
        Verdict.SUSPICIOUS -> "🟠 可疑 SUSPICIOUS" to Color.parseColor("#E65100")
        Verdict.HIGH_RISK -> "🔴 高危 HIGH_RISK" to Color.parseColor("#C62828")
        Verdict.COMPROMISED -> "⛔ 不可信 COMPROMISED" to red
        Verdict.UNKNOWN -> "❔ 未知 UNKNOWN" to sub
    }

    private fun scoreColor(s: Int) = when {
        s < 20 -> green
        s < 40 -> Color.parseColor("#558B2F")
        s < 70 -> Color.parseColor("#E65100")
        else -> Color.parseColor("#C62828")
    }

    private fun severityColor(s: Severity) = when (s) {
        Severity.CRITICAL -> red
        Severity.HIGH -> Color.parseColor("#C62828")
        Severity.MEDIUM -> Color.parseColor("#E65100")
        Severity.LOW -> Color.parseColor("#F9A825")
        Severity.INFO -> sub
    }

    private fun sevMark(s: Severity) = when (s) {
        Severity.CRITICAL -> "⛔"; Severity.HIGH -> "🔴"; Severity.MEDIUM -> "🟠"
        Severity.LOW -> "🟡"; Severity.INFO -> "⚪"
    }

    private fun logSummary(r: RiskReport) {
        val sb = StringBuilder("verdict=${r.verdict} score=${r.score} blockers=${r.blockingSignals.size} signals=${r.signals.size}\n")
        r.blockingSignals.forEach { sb.append("  BLOCK ${it.id} [${it.source}]\n") }
        r.signals.forEach { sb.append("  [${it.severity}] ${it.id} (${it.confidence}) [${it.source}]\n") }
        Log.i("DevCheck", "\n$sb")
    }

    private fun copyJson() {
        val json = report?.toJson() ?: return toast("请先完成检测")
        (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager)
            .setPrimaryClip(ClipData.newPlainText("DevCheck report", json))
        toast("JSON 已复制 (${json.length} 字)")
    }

    private fun exportJson() {
        val json = report?.toJson() ?: return toast("请先完成检测")
        val file = File(getExternalFilesDir(null) ?: filesDir, "devcheck-report.json")
        if (runCatching { file.writeText(json) }.isFailure) return toast("导出失败")
        toast("已导出: ${file.absolutePath}")
        runCatching {
            startActivity(
                Intent.createChooser(
                    Intent(Intent.ACTION_SEND).apply {
                        type = "application/json"
                        putExtra(Intent.EXTRA_SUBJECT, "DevCheck report")
                        putExtra(Intent.EXTRA_TEXT, json)
                    },
                    "导出 DevCheck 报告",
                ),
            )
        }
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    private companion object {
        const val CATEGORY_CAP = 70
        const val REQ_LOCATION = 1001
    }
}
