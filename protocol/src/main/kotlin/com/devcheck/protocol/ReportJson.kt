package com.devcheck.protocol

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val reportJson = Json {
    prettyPrint = true
    encodeDefaults = true
    explicitNulls = false
}

private val compactJson = Json {
    encodeDefaults = true
    explicitNulls = false
}

/** 把检测结果序列化为（美化的）JSON，用于 adb 导出 / 排查 / 上报。 */
fun RiskReport.toJson(): String = reportJson.encodeToString(this)

/** 紧凑单行 JSON（无换行），用于 logcat 分块导出等对换行敏感的通道。 */
fun RiskReport.toCompactJson(): String = compactJson.encodeToString(this)
