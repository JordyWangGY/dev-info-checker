package com.devcheck.core

import android.util.Base64

/**
 * 轻量字符串混淆：把检测特征（su/magisk 路径、frida/xposed 关键字等）以 XOR+Base64 存储，
 * 运行时解码。目的：阻止攻击者用 `strings` / 反编译直接 grep 出我们检测了哪些特征。
 *
 * 注意：这是抗静态分析的「提高成本」手段，不是强加密；运行时明文仍在内存中。
 */
internal object Secrets {
    private const val K = 0x5A

    fun dec(b64: String): String {
        val raw = Base64.decode(b64, Base64.NO_WRAP)
        val out = ByteArray(raw.size) { (raw[it].toInt() xor K).toByte() }
        return String(out, Charsets.UTF_8)
    }

    fun list(vararg b64: String): List<String> = b64.map { dec(it) }
}
