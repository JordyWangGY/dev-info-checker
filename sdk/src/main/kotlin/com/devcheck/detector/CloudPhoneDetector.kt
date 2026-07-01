package com.devcheck.detector

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
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

        // 9) VM 固件：真 ARM 手机无 DMI/无 qemu_fw_cfg；DMI 厂商=QEMU/云厂商 或 firmware 含 qemu_fw_cfg
        val dmiVendor = read(ctx, "/sys/class/dmi/id/sys_vendor")
        val dmiProduct = read(ctx, "/sys/class/dmi/id/product_name")
        val fw = File("/sys/firmware").list()?.toList().orEmpty()
        val dmiBlob = "$dmiVendor $dmiProduct".lowercase()
        val vmVendors = listOf("qemu", "google", "amazon", "alibaba", "tencent", "huawei cloud", "microsoft", "vmware", "virtualbox", "oracle", "bochs", "kvm")
        val dmiHit = vmVendors.any { dmiBlob.contains(it) } || dmiBlob.contains("virtual")
        if (fw.contains("qemu_fw_cfg") || dmiHit) {
            out += sig(Signals.CLOUD_VM_FIRMWARE, Severity.HIGH, 0.85f, mapOf(
                "dmi_vendor" to dmiVendor, "dmi_product" to dmiProduct,
                "firmware" to fw.joinToString().ifEmpty { "<none>" },
            ))
        }

        // 10) 传感器厂商：模拟器/云机用 AOSP 默认传感器 HAL；真机是 BOSCH/STMicro/InvenSense 等
        sensorVendorAnomaly(ctx)?.let { (name, vendor) ->
            out += sig(Signals.CLOUD_SENSOR_VENDOR, Severity.MEDIUM, 0.6f, mapOf("sensor" to name, "vendor" to vendor))
        }

        // 11) virtio 半虚拟化设备中断（难伪造的鲁棒性信号；真机无 virtio）
        val irq = read(ctx, "/proc/interrupts")
        val virtioLines = irq.lineSequence().count { it.contains("virtio") }
        if (virtioLines > 0) {
            out += sig(Signals.CLOUD_VIRTIO, Severity.HIGH, 0.8f, mapOf("virtio_irq_lines" to virtioLines.toString()))
        }

        // 11) 采集（INFO，0 分）：真实硬件缺失面 + 汇总，喂服务端一致性复核
        val socAbsent = !File("/sys/devices/soc0").exists()
        val cpufreqAbsent = !File("/sys/devices/system/cpu/cpu0/cpufreq").exists()
        val thermalAbsent = File("/sys/class/thermal").list()?.none { it.startsWith("thermal_zone") } ?: true
        val vmDevs = File("/dev").list()?.count { it.startsWith("vport") || it.startsWith("hvc") } ?: 0
        out += sig(Signals.CLOUD_INFO, Severity.INFO, 1f, mapOf(
            "os_version" to (System.getProperty("os.version") ?: ""),
            "soc0_absent" to socAbsent.toString(),
            "cpufreq_absent" to cpufreqAbsent.toString(),
            "thermal_absent" to thermalAbsent.toString(),
            "pci_count" to pci.size.toString(),
            "net_ifaces" to nets.joinToString(),
            "virtio_serial_ports" to vmDevs.toString(),
            "firmware" to fw.joinToString(),
            "eth0_speed" to read(ctx, "/sys/class/net/eth0/speed"),
            "vda_rotational" to read(ctx, "/sys/block/vda/queue/rotational"),
        ))

        out
    }

    /** 核心物理传感器(加速度/陀螺/磁力)的 vendor 若是 AOSP/Goldfish 默认 HAL → 伪造。返回 (名, 厂商)。 */
    private fun sensorVendorAnomaly(ctx: DetectContext): Pair<String, String>? {
        val sm = ctx.app.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return null
        val types = listOf(Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE, Sensor.TYPE_MAGNETIC_FIELD)
        for (t in types) {
            val s = sm.getDefaultSensor(t) ?: continue
            val vendor = s.vendor.orEmpty()
            val low = vendor.lowercase()
            if (low.contains("aosp") || low.contains("goldfish") || low.contains("android open source") || low.contains("ranchu")) {
                return s.name to vendor
            }
        }
        return null
    }

    private fun read(ctx: DetectContext, path: String): String {
        val n = ctx.native.readText(path)
        val raw = if (n.isNotEmpty()) n else runCatching { File(path).readText() }.getOrDefault("")
        return raw.trim()
    }

    private fun sig(id: String, sev: Severity, conf: Float, ev: Map<String, String>) =
        Signal(id, category, sev, conf, Source.JAVA, ev)
}
