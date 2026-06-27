package com.devcheck.detector

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.NetworkInterface

/** VPN / 代理检测（仅参考：正常用户也会用 VPN，低权重）。 */
internal class NetworkDetector : Detector {
    override val id = "network"
    override val category = Category.NETWORK

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()

        val cm = ctx.app.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val caps = cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) }
        val vpnByCaps = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val vpnByIface = runCatching {
            NetworkInterface.getNetworkInterfaces().toList().any {
                it.isUp && (it.name.startsWith("tun") || it.name.startsWith("ppp") || it.name.startsWith("tap"))
            }
        }.getOrDefault(false)
        if (vpnByCaps || vpnByIface) {
            out += Signal(
                Signals.NETWORK_VPN, category, Severity.LOW, 0.4f, Source.JAVA,
                mapOf("by_caps" to vpnByCaps.toString(), "by_iface" to vpnByIface.toString()),
            )
        }

        val proxyHost = System.getProperty("http.proxyHost")
        if (!proxyHost.isNullOrBlank()) {
            out += Signal(
                Signals.NETWORK_PROXY, category, Severity.LOW, 0.4f, Source.JAVA,
                mapOf("host" to proxyHost, "port" to (System.getProperty("http.proxyPort") ?: "")),
            )
        }

        out
    }
}
