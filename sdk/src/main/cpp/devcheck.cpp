// DevCheck 原生核心：关键判定下沉到 native，并尽量用「直接 syscall」绕过可能被 hook 的 libc。
// 对应 Kotlin 侧 com.devcheck.nativebridge.NativeProbe 的 external 方法。
#include <jni.h>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <linux/stat.h>   // struct statx / STATX_BTIME（直接走 __NR_statx，绕过 libc stat hook）

// —— 字符串混淆：可疑库名以 XOR(0x5A) 存储，避免 `strings` 直接 grep 出检测特征 ——
static const unsigned char XOR_KEY = 0x5A;
static std::string deob(const unsigned char *d, size_t n) {
    std::string s;
    s.resize(n);
    for (size_t i = 0; i < n; i++) s[i] = (char) (d[i] ^ XOR_KEY);
    return s;
}
#define DEOB(a) deob(a, sizeof(a))

static const unsigned char N0[]  = {0x3c,0x28,0x33,0x3e,0x3b};                     // frida
static const unsigned char N1[]  = {0x3d,0x2f,0x37};                              // gum
static const unsigned char N2[]  = {0x3d,0x3b,0x3e,0x3d,0x3f,0x2e};               // gadget
static const unsigned char N3[]  = {0x36,0x33,0x34,0x30,0x3f,0x39,0x2e,0x35,0x28};// linjector
static const unsigned char N4[]  = {0x22,0x2a,0x35,0x29,0x3f,0x3e};               // xposed
static const unsigned char N5[]  = {0x36,0x29,0x2a,0x3e};                         // lspd
static const unsigned char N6[]  = {0x36,0x29,0x2a,0x3b,0x2e,0x39,0x32};          // lspatch
static const unsigned char N7[]  = {0x3f,0x3e,0x22,0x2a};                         // edxp
static const unsigned char N8[]  = {0x28,0x33,0x28,0x2f};                         // riru
static const unsigned char N9[]  = {0x20,0x23,0x3d,0x33,0x29,0x31};               // zygisk
static const unsigned char N10[] = {0x29,0x3b,0x34,0x3e,0x32,0x35,0x35,0x31};     // sandhook
static const unsigned char N11[] = {0x2d,0x32,0x3b,0x36,0x3f};                    // whale
static const unsigned char N12[] = {0x29,0x2f,0x38,0x29,0x2e,0x28,0x3b,0x2e,0x3f};// substrate
static const unsigned char N13[] = {0x37,0x3b,0x3d,0x33,0x29,0x31};               // magisk

static std::vector<std::string> suspicious_needles() {
    return {
        DEOB(N0), DEOB(N1), DEOB(N2), DEOB(N3), DEOB(N4), DEOB(N5), DEOB(N6),
        DEOB(N7), DEOB(N8), DEOB(N9), DEOB(N10), DEOB(N11), DEOB(N12), DEOB(N13),
    };
}

// 用 syscall(openat/read/close) 直接读文件，绕过 libc 的 open/fopen/read hook。
static std::string read_proc(const char *path) {
    int fd = (int) syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return std::string();
    std::string out;
    char buf[4096];
    for (;;) {
        long n = syscall(__NR_read, fd, buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, (size_t) n);
    }
    syscall(__NR_close, fd);
    return out;
}

static jobjectArray toStringArray(JNIEnv *env, const std::vector<std::string> &v) {
    jclass cls = env->FindClass("java/lang/String");
    jobjectArray arr = env->NewObjectArray((jsize) v.size(), cls, nullptr);
    for (jsize i = 0; i < (jsize) v.size(); i++) {
        jstring s = env->NewStringUTF(v[(size_t) i].c_str());
        env->SetObjectArrayElement(arr, i, s);
        env->DeleteLocalRef(s);
    }
    return arr;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_devcheck_nativebridge_NativeProbe_nativeTracerPid(JNIEnv *, jobject) {
    std::string status = read_proc("/proc/self/status");
    if (status.empty()) return -1;
    const char *key = "TracerPid:";
    size_t pos = status.find(key);
    if (pos == std::string::npos) return 0;
    return (jint) strtol(status.c_str() + pos + strlen(key), nullptr, 10);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_devcheck_nativebridge_NativeProbe_nativePathExists(JNIEnv *env, jobject, jstring jpath) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) return JNI_FALSE;
    long r = syscall(__NR_faccessat, AT_FDCWD, path, F_OK); // 3 参内核 faccessat，绕过 libc
    env->ReleaseStringUTFChars(jpath, path);
    return r == 0 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_devcheck_nativebridge_NativeProbe_nativeSuspiciousMaps(JNIEnv *env, jobject) {
    std::vector<std::string> needles = suspicious_needles();
    std::string maps = read_proc("/proc/self/maps");
    std::vector<std::string> hits;
    size_t start = 0;
    while (start < maps.size()) {
        size_t end = maps.find('\n', start);
        if (end == std::string::npos) end = maps.size();
        std::string line = maps.substr(start, end - start);
        start = end + 1;
        std::string low = line;
        for (auto &c : low) c = (char) tolower((unsigned char) c);
        for (const auto &n : needles) {
            if (low.find(n) != std::string::npos) { hits.push_back(line); break; }
        }
    }
    return toStringArray(env, hits);
}

// —— inline hook 检测：目标函数序言是否被改写为常见 hook 跳板（仅匹配明确的跳板形态，误报≈0）——
static bool looks_trampolined(const void *fn) {
    if (!fn) return false;
    const uint8_t *p = (const uint8_t *) fn;
#if defined(__aarch64__)
    uint32_t i0 = *(const uint32_t *) p;
    uint32_t i1 = *(const uint32_t *) (p + 4);
    if ((i0 == 0x58000050u && i1 == 0xD61F0200u) ||   // LDR x16,#8 ; BR x16
        (i0 == 0x58000051u && i1 == 0xD61F0220u))     // LDR x17,#8 ; BR x17
        return true;
#elif defined(__arm__)
    uint32_t i0 = *(const uint32_t *) p;
    if (i0 == 0xE51FF004u) return true;                // LDR pc,[pc,#-4]
#elif defined(__x86_64__) || defined(__i386__)
    if (p[0] == 0xE9) return true;                     // jmp rel32
    if (p[0] == 0xFF && p[1] == 0x25) return true;     // jmp [rip+disp]
    if (p[0] == 0x68 && p[5] == 0xC3) return true;     // push imm32 ; ret
#endif
    return false;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_devcheck_nativebridge_NativeProbe_nativeInlineHooked(JNIEnv *env, jobject) {
    static const char *fns[] = {
        "open", "openat", "read", "fopen", "dlopen", "dlsym", "connect",
        "android_dlopen_ext", "mmap",
    };
    std::vector<std::string> hooked;
    for (const char *name : fns) {
        void *f = dlsym(RTLD_DEFAULT, name);
        if (looks_trampolined(f)) hooked.emplace_back(name);
    }
    return toStringArray(env, hooked);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_devcheck_nativebridge_NativeProbe_nativeCodeWritable(JNIEnv *, jobject) {
    std::string maps = read_proc("/proc/self/maps");
    size_t start = 0;
    while (start < maps.size()) {
        size_t end = maps.find('\n', start);
        if (end == std::string::npos) end = maps.size();
        std::string line = maps.substr(start, end - start);
        start = end + 1;
        if (line.find("libdevcheck.so") == std::string::npos) continue;
        size_t sp = line.find(' ');
        if (sp == std::string::npos || sp + 3 >= line.size()) continue;
        bool w = line[sp + 2] == 'w';  // perms: r w x p
        bool x = line[sp + 3] == 'x';
        if (w && x) return JNI_TRUE;   // 代码段同时可写可执行 = 被打补丁前置条件
    }
    return JNI_FALSE;
}

// 直接读系统属性，绕过可能被 hook 的 Java SystemProperties / getprop
extern "C" JNIEXPORT jstring JNICALL
Java_com_devcheck_nativebridge_NativeProbe_nativeGetProp(JNIEnv *env, jobject, jstring jkey) {
    const char *key = env->GetStringUTFChars(jkey, nullptr);
    char buf[PROP_VALUE_MAX] = {0};
    int n = key ? __system_property_get(key, buf) : 0;
    if (key) env->ReleaseStringUTFChars(jkey, key);
    return env->NewStringUTF(n > 0 ? buf : "");
}

// 文件真实创建时间(birth time)：syscall(statx, STATX_BTIME)。毫秒 epoch；
// 不支持/路径不存在/无 btime 返回 -1（上层回落 mtime）。直接 syscall 绕过 libc stat hook。
extern "C" JNIEXPORT jlong JNICALL
Java_com_devcheck_nativebridge_NativeProbe_nativeCrtime(JNIEnv *env, jobject, jstring jpath) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) return -1;
#if defined(__NR_statx)
    struct statx stx;
    memset(&stx, 0, sizeof(stx));
    long r = syscall(__NR_statx, AT_FDCWD, path, 0, STATX_BTIME, &stx);
    env->ReleaseStringUTFChars(jpath, path);
    if (r != 0) return -1;
    if ((stx.stx_mask & STATX_BTIME) == 0) return -1; // 文件系统未提供 btime
    if (stx.stx_btime.tv_sec <= 0) return -1;
    return (jlong) stx.stx_btime.tv_sec * 1000 + (jlong) (stx.stx_btime.tv_nsec / 1000000);
#else
    env->ReleaseStringUTFChars(jpath, path);
    return -1;
#endif
}

// 直接 syscall(openat/read) 读小文件（/proc、/sys、selinuxfs），绕过 libc open/read hook。
extern "C" JNIEXPORT jstring JNICALL
Java_com_devcheck_nativebridge_NativeProbe_nativeReadText(JNIEnv *env, jobject, jstring jpath) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    std::string out = path ? read_proc(path) : std::string();
    if (path) env->ReleaseStringUTFChars(jpath, path);
    return env->NewStringUTF(out.c_str());
}
