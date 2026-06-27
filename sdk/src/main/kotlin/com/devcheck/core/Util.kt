package com.devcheck.core

import java.io.File
import java.security.MessageDigest

/** SHA-256 → 大写十六进制。 */
internal fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02X".format(it) }

/** 读取 /proc/self/maps（Java 兜底；原生核心在 1.2 提供抗 hook 版本）。 */
internal fun readSelfMaps(): List<String> =
    runCatching { File("/proc/self/maps").readLines() }.getOrDefault(emptyList())

/** 读取本进程所有线程名（每个 /proc/self/task/<tid>/comm）。 */
internal fun readThreadNames(): List<String> =
    runCatching {
        File("/proc/self/task").listFiles()?.mapNotNull { t ->
            runCatching { File(t, "comm").readText().trim() }.getOrNull()
        }.orEmpty()
    }.getOrDefault(emptyList())
