package com.devcheck.protocol

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val reportJson = Json {
    prettyPrint = true
    encodeDefaults = true
    explicitNulls = false
}

/** 把检测结果序列化为（美化的）JSON，用于 adb 导出 / 排查 / 上报。 */
fun RiskReport.toJson(): String = reportJson.encodeToString(this)
