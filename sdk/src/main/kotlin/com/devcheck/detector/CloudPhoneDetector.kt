package com.devcheck.detector

import com.devcheck.protocol.Category
import com.devcheck.protocol.Severity
import com.devcheck.protocol.Signal
import com.devcheck.protocol.Signals
import com.devcheck.protocol.Source
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 云手机 / 容器化 Android 检测（redroid 类 **ARM-on-ARM 共享内核容器**）。
 *
 * 云机跑在真 ARM 服务器上，经典 x86/QEMU/goldfish 与 clocksource(kvm-clock) 检测**失效**；
 * 真正暴露它的是：宿主 Linux 内核串、容器痕迹、虚拟磁盘/声卡/网卡/PCI、真实硬件缺失。
 * 读取尽量走 [NativeProbe.readText]（syscall，抗 hook），目录用 File.list。
 *
 * **全部仅计分、非阻断点**：ARM 云机上单条信号都可能被针对性伪造（且 `ro.*` 属性可被覆盖），
 * 靠多信号叠加 + 服务端一致性定案。详见 CLOUDPHONE_DETECTION.md。
 */
internal class CloudPhoneDetector : Detector {
    override val id = "cloud"
    override val category = Category.EMULATOR

    override suspend fun detect(ctx: DetectContext): List<Signal> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Signal>()

        // 1) 宿主 Linux 内核串：Android 是 clang 构建的 vendor 内核，绝不含 Ubuntu/gcc/-generic
        val version = read(ctx, "/proc/version").ifEmpty { System.getProperty("os.version").orEmpty() }
        val v = version.lowercase()
        if (listOf("ubuntu", "-generic", "gcc version", "buildd@", "debian").any { v.contains(it) }) {
            out += sig(Signals.CLOUD_KERNEL, Severity.HIGH, 0.85f, mapOf("version" to version.take(120)))
        }

        // 2) 虚拟磁盘布局：virtio vda / CD-ROM sr0 / 无真实 mmcblk|UFS
        val parts = read(ctx, "/proc/partitions")
        val hasVirtio = Regex("\\bvd[a-z]\\b").containsMatchIn(parts)
        val hasCdrom = Regex("\\bsr\\d\\b").containsMatchIn(parts)
        val hasRealDisk = Regex("mmcblk|\\bsd[a-z]\\b|ufs").containsMatchIn(parts)
        if (hasVirtio || hasCdrom || (parts.isNotEmpty() && !hasRealDisk)) {
            out += sig(Signals.CLOUD_DISK, Severity.HIGH, 0.8f, mapOf(
                "virtio_vd" to hasVirtio.toString(), "cdrom_sr" to hasCdrom.toString(), "real_disk" to hasRealDisk.toString(),
            ))
        }

        // 3) PCI 总线：真 ARM 手机用 platform/AMBA，无 PCI；有 PCI=QEMU/服务器
        val pci = File("/sys/bus/pci/devices").list()?.filter { it.isNotBlank() }.orEmpty()
        if (pci.isNotEmpty()) {
            out += sig(Signals.CLOUD_PCI, Severity.HIGH, 0.8f, mapOf("count" to pci.size.toString(), "sample" to pci.take(3).joinToString()))
        }

        // 4) 虚拟输入设备：无真实触屏驱动，尽是 QEMU/Virtual
        val input = read(ctx, "/proc/bus/input/devices").lowercase()
        val inputHits = listOf("qemu", "virtual", "goldfish", "gadget").filter { input.contains(it) }
        if (inputHits.isNotEmpty()) {
            out += sig(Signals.CLOUD_INPUT, Severity.HIGH, 0.8f, mapOf("markers" to inputHits.joinToString()))
        }

        // 5) 容器 cgroup 痕迹：Android 用 init，无 systemd/docker/lxc/kubepods
        val cg = read(ctx, "/proc/self/cgroup").lowercase()
        val cgHits = listOf("name=systemd", "/docker", "/lxc", "/kubepods").filter { cg.contains(it) }
        if (cgHits.isNotEmpty()) {
            out += sig(Signals.CLOUD_CGROUP, Severity.HIGH, 0.75f, mapOf("markers" to cgHits.joinToString()))
        }

        // 6) 网络接口：只有 eth0 而无任何无线/蜂窝口 = 数据中心网卡
        val nets = File("/sys/class/net").list()?.toList().orEmpty()
        val wireless = nets.any { it.startsWith("wlan") || it.startsWith("rmnet") || it.startsWith("ccmni") || it.startsWith("radio") }
        if (nets.contains("eth0") && !wireless) {
            out += sig(Signals.CLOUD_NET, Severity.MEDIUM, 0.6f, mapOf("ifaces" to nets.joinToString()))
        }

        // 7) sysfs 无电池：真机必有 power_supply/battery；framework 却能报电量=HAL 假造
        val ps = File("/sys/class/power_supply").list()?.toList()
        if (ps != null && ps.none { it.lowercase().contains("battery") }) {
            out += sig(Signals.CLOUD_NO_BATTERY, Severity.MEDIUM, 0.6f, mapOf("power_supply" to ps.joinToString().ifEmpty { "<empty>" }))
        }

        // 8) 虚拟声卡：真 ARM 手机是 qcom/WCD，不可能是 Intel HD Audio / QEMU
        val sound = read(ctx, "/proc/asound/cards").lowercase()
        val soundHits = listOf("hda intel", "hda-intel", "qemu", "virtio", "ac97").filter { sound.contains(it) }
        if (soundHits.isNotEmpty()) {
            out += sig(Signals.CLOUD_SOUNDCARD, Severity.MEDIUM, 0.6f, mapOf("markers" to soundHits.joinToString()))
        }

        // 9) 采集（INFO，0 分）：真实硬件缺失面 + 汇总，喂服务端一致性复核
        val socAbsent = !File("/sys/devices/soc0").exists()
        val cpufreqAbsent = !File("/sys/devices/system/cpu/cpu0/cpufreq").exists()
        val thermalAbsent = File("/sys/class/thermal").list()?.none { it.startsWith("thermal_zone") } ?: true
        out += sig(Signals.CLOUD_INFO, Severity.INFO, 1f, mapOf(
            "os_version" to (System.getProperty("os.version") ?: ""),
            "soc0_absent" to socAbsent.toString(),
            "cpufreq_absent" to cpufreqAbsent.toString(),
            "thermal_absent" to thermalAbsent.toString(),
            "pci_count" to pci.size.toString(),
            "net_ifaces" to nets.joinToString(),
        ))

        out
    }

    private fun read(ctx: DetectContext, path: String): String {
        val n = ctx.native.readText(path)
        val raw = if (n.isNotEmpty()) n else runCatching { File(path).readText() }.getOrDefault("")
        return raw.trim()
    }

    private fun sig(id: String, sev: Severity, conf: Float, ev: Map<String, String>) =
        Signal(id, category, sev, conf, Source.JAVA, ev)
}
