#!/usr/bin/env bash
#
# DevCheck —— 一键构建 / 安装 / 运行脚本
#
#   ./install.sh [命令] [设备序列号]
#
#   设备选择（设备类命令必填，支持模糊匹配）：
#     ./install.sh run 15039               # 模糊匹配，唯一命中 → 192.168.2.43:15039
#     ./install.sh run 192.168.2.43:15039  # 或完整序列号
#     ANDROID_SERIAL=<serial> ./install.sh run   # 或环境变量(精确)
#     ./install.sh devices                 # 列出已连接设备
#
#   命令：
#     run        (默认) 构建 → 安装 → 启动 → 打印一次检测报告
#     build      仅构建 sample debug APK
#     install    构建(按需) → 安装到已连接设备/模拟器
#     aar        构建可集成的 SDK release AAR
#     test       运行 protocol 层打分/阻断点单元测试
#     logcat     持续跟踪检测日志 (tag: DevCheck)
#     export     通过 adb 触发检测并导出 JSON 结果文档
#     uninstall  卸载示例 App
#
#   环境变量（可覆盖默认值）：
#     JAVA_HOME      默认 /usr/lib/jvm/java-17-openjdk-amd64
#     ANDROID_HOME   默认 $HOME/Android/Sdk
#     ANDROID_SERIAL 指定目标设备（多设备时）
#
set -euo pipefail

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

ADB="$ANDROID_HOME/platform-tools/adb"
APK="$ROOT/sample/build/outputs/apk/debug/sample-debug.apk"
PKG="com.devcheck.sample"
ACT="$PKG/.MainActivity"

CMD="${1:-run}"
DEVICE_PATTERN="${2:-}"   # 设备选择器（必填于设备类命令）：支持模糊匹配，grep 出唯一完整序列号

c_info=$'\033[1;36m'; c_ok=$'\033[1;32m'; c_err=$'\033[1;31m'; c_off=$'\033[0m'
log()  { printf '%s[devcheck]%s %s\n' "$c_info" "$c_off" "$*"; }
ok()   { printf '%s[devcheck]%s %s\n' "$c_ok"   "$c_off" "$*"; }
die()  { printf '%s[devcheck] %s%s\n' "$c_err" "$*" "$c_off" >&2; exit 1; }

check_jdk() {
    "$JAVA_HOME/bin/java" -version >/dev/null 2>&1 || die "JAVA_HOME 无效：$JAVA_HOME（需要 JDK 17）"
}

connected() { "$ADB" devices | awk 'NR>1 && $2=="device"{print $1}'; }

# 必须显式指定设备（绝不自动选）；参数支持模糊匹配，唯一命中才放行。
require_device() {
    [ -x "$ADB" ] || die "找不到 adb：$ADB"
    local all; all="$(connected)"
    [ -n "$all" ] || die "没有已连接的设备/模拟器。"

    if [ -n "$DEVICE_PATTERN" ]; then
        local matches n; matches="$(printf '%s\n' "$all" | grep -- "$DEVICE_PATTERN" || true)"
        n="$(printf '%s\n' "$matches" | grep -c . || true)"
        case "$n" in
            0) die "没有设备匹配 '$DEVICE_PATTERN'。当前设备：
$all" ;;
            1) export ANDROID_SERIAL="$matches"; log "目标设备：${ANDROID_SERIAL}（模糊匹配 '$DEVICE_PATTERN'）" ;;
            *) die "'$DEVICE_PATTERN' 匹配到多台，请更精确：
$matches" ;;
        esac
        return
    fi

    if [ -n "${ANDROID_SERIAL:-}" ]; then
        printf '%s\n' "$all" | grep -qx "$ANDROID_SERIAL" \
            || die "ANDROID_SERIAL='$ANDROID_SERIAL' 未连接。当前设备：
$all"
        log "目标设备：$ANDROID_SERIAL"
        return
    fi

    die "必须指定设备（支持模糊匹配）：
  ./install.sh $CMD <设备关键字>     例如  ./install.sh $CMD $(printf '%s' "$all" | head -1 | grep -oE '[0-9]+$')
  ./install.sh devices               查看全部
当前设备：
$all"
}

do_devices() {
    [ -x "$ADB" ] || die "找不到 adb：$ADB"
    "$ADB" devices -l
}

do_build() {
    check_jdk
    log "构建 sample debug APK ..."
    ./gradlew :sample:assembleDebug --console=plain
    ok "APK → $APK"
}

do_aar() {
    check_jdk
    log "构建 SDK release AAR ..."
    ./gradlew :sdk:assembleRelease --console=plain
    ok "AAR → $ROOT/sdk/build/outputs/aar/sdk-release.aar"
}

do_test() {
    check_jdk
    log "运行打分/阻断点单元测试 ..."
    ./gradlew :protocol:test --console=plain
    ok "测试通过"
}

do_install() {
    [ -f "$APK" ] || do_build
    require_device
    log "安装到设备（-r 覆盖、-g 自动授权）..."
    "$ADB" install -r -g "$APK"
    ok "已安装：$PKG"
}

do_run() {
    do_build
    do_install
    log "启动 $ACT ..."
    "$ADB" logcat -c || true
    "$ADB" shell am start -n "$ACT" >/dev/null
    log "等待检测完成并打印报告（完整结果也显示在 App 界面）..."
    sleep 2
    echo "----------------------------------------------------------------------"
    "$ADB" logcat -d -s "DevCheck:I" "*:S"
    echo "----------------------------------------------------------------------"
    ok "完成。如需持续跟踪：./install.sh logcat"
}

do_logcat() {
    require_device
    log "跟踪检测日志（Ctrl+C 退出）..."
    exec "$ADB" logcat -s "DevCheck:I" "*:S"
}

do_uninstall() {
    require_device
    "$ADB" uninstall "$PKG" && ok "已卸载：$PKG"
}

do_export() {
    require_device
    local dst="$ROOT/devcheck-report.json"
    log "触发导出广播 ..."
    "$ADB" shell am broadcast -n "$PKG/com.devcheck.export.ExportReceiver" >/dev/null
    log "等待检测完成 ..."
    sleep 3
    if "$ADB" exec-out run-as "$PKG" cat files/devcheck-report.json > "$dst" 2>/dev/null && [ -s "$dst" ]; then
        ok "已导出 → $dst"
    elif "$ADB" pull "/sdcard/Android/data/$PKG/files/devcheck-report.json" "$dst" >/dev/null 2>&1 && [ -s "$dst" ]; then
        ok "已导出 → $dst"
    else
        die "读取失败。改用：adb logcat -s DevCheck:I（看 DEVCHECK_REPORT_BEGIN/END 之间的 JSON）"
    fi
    echo "----------------------------------------------------------------------"
    cat "$dst"
    echo "----------------------------------------------------------------------"
}

case "${1:-run}" in
    run)        do_run ;;
    build)      do_build ;;
    install)    do_install ;;
    aar)        do_aar ;;
    test)       do_test ;;
    logcat)     do_logcat ;;
    export)     do_export ;;
    devices)    do_devices ;;
    uninstall)  do_uninstall ;;
    -h|--help|help) sed -n '2,30p' "$0" | sed 's/^#//' ;;
    *) die "未知命令：$1（试试 ./install.sh help）" ;;
esac
