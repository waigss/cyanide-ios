//
//  KernelUserMemory.m
//  Cyanide
//
//  不附加目标进程、不创建线程，直接从内核页表读目标进程的用户态内存。
//
//  地址翻译：proc → task → vm_map → pmap → 根页表(tte)
//            tte - ttep = 页表窗口线性偏移
//            16KB 页、3 级：L0 VA[47:36] / L1 VA[35:25] / L2 VA[24:14] / 页内 [13:0]
//            页表项物理地址 = bit[47:14]
//
//  dyld 模块表定位：先用 _dyld_image_count() 作基准，在自己 task 结构里校准出
//  all_image_info_addr 的偏移，再把这个偏移用到目标进程上（确定性，不靠猜）。
//

#import "KernelUserMemory.h"

#import "../kexploit/krw.h"
#import "../kexploit/kutils.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/offsets.h"
#import "../kexploit/xpaci.h"

#import "CyanideLog.h"

#import <string.h>
#import <stdlib.h>
#import <mach-o/dyld.h>

static const uint64_t kPageSize      = 0x4000ULL;
static const uint64_t kPageMask      = 0x3FFFULL;
static const uint64_t kPaMask        = 0x0000FFFFFFFFC000ULL;   // 页表项物理地址 bit[47:14]
static const unsigned int kL0Shift   = 36;
static const unsigned int kL1Shift   = 25;
static const unsigned int kL2Shift   = 14;
static const uint64_t kL0IndexMask   = 0xFFFULL;
static const uint64_t kL1IndexMask   = 0x7FFULL;
static const uint64_t kL2IndexMask   = 0x7FFULL;

// _vm_map.pmap 偏移（对照 xnu-11417 struct _vm_map，已在 iOS 18.5 实测验证）
static const uint64_t kPmapOffsetInVmMap = 0x40;

static uint64_t gPmap = 0;
static uint64_t gRootTable = 0;
static uint64_t gWindowOffset = 0;
static uint64_t gMapMin = 0;
static uint64_t gMapMax = 0;
static uint64_t gTask = 0;
static uint64_t gInfoOffset = 0;      // task 里 all_image_info_addr 的偏移
static BOOL gPrepared = NO;

// ---------------------------------------------------------------------------
// 上下文准备
// ---------------------------------------------------------------------------

static BOOL kum_prepare_context(uint64_t proc)
{
    gPmap = 0;
    gRootTable = 0;
    gWindowOffset = 0;
    gMapMin = 0;
    gMapMax = 0;
    gTask = 0;
    gPrepared = NO;

    if (!kexploit_krw_ready()) return NO;
    if (!is_kaddr_valid(proc)) return NO;

    uint64_t task = proc_task(proc);
    if (!is_kaddr_valid(task)) return NO;

    uint64_t map = kread_ptr(task + off_task_map);
    if (!is_kaddr_valid(map)) return NO;

    uint64_t pmap = kread_ptr(map + kPmapOffsetInVmMap);
    if (!is_kaddr_valid(pmap)) return NO;

    uint64_t tte = kread_ptr(pmap + 0x00);
    uint64_t ttep = kread64(pmap + 0x08);
    if (!is_kaddr_valid(tte) || ttep == 0) return NO;

    gTask = task;
    gPmap = pmap;
    gRootTable = tte;
    gWindowOffset = tte - ttep;
    gMapMin = kread64(map + 0x20);
    gMapMax = kread64(map + 0x28);
    gPrepared = YES;
    return YES;
}

// 当前上下文里把一段用户地址读到本地；地址未映射返回 NO。
static BOOL kum_read_context(uint64_t va, void *dst, size_t len)
{
    if (!gPrepared || !dst || len == 0) return NO;
    if (va < gMapMin || va + len > gMapMax) return NO;

    uint8_t *out = (uint8_t *)dst;
    size_t remaining = len;
    uint64_t cursor = va;

    while (remaining > 0) {
        uint64_t l0Index = (cursor >> kL0Shift) & kL0IndexMask;
        uint64_t e0 = kread64(gRootTable + l0Index * 8);
        if ((e0 & 1) == 0) return NO;

        uint64_t l1Kva = (e0 & kPaMask) + gWindowOffset;
        uint64_t l1Index = (cursor >> kL1Shift) & kL1IndexMask;
        uint64_t e1 = kread64(l1Kva + l1Index * 8);
        if ((e1 & 1) == 0 || (e1 & 2) == 0) return NO;

        uint64_t l2Kva = (e1 & kPaMask) + gWindowOffset;
        uint64_t l2Index = (cursor >> kL2Shift) & kL2IndexMask;
        uint64_t e2 = kread64(l2Kva + l2Index * 8);
        if ((e2 & 1) == 0 || (e2 & 2) == 0) return NO;

        uint64_t pageKva = (e2 & kPaMask) + gWindowOffset;
        uint64_t inPage = cursor & kPageMask;
        uint64_t avail = kPageSize - inPage;
        size_t chunk = (size_t)((remaining < avail) ? remaining : avail);

        kreadbuf(pageKva + inPage, out, (uint64_t)chunk);

        out += chunk;
        cursor += chunk;
        remaining -= chunk;
    }

    return YES;
}

// ---------------------------------------------------------------------------
// 用自身进程校准 all_image_info_addr 的偏移
// ---------------------------------------------------------------------------

static void kum_calibrate(void)
{
    if (gInfoOffset != 0 || !gPrepared) return;

    uint32_t expected = _dyld_image_count();
    if (expected == 0) return;

    for (uint64_t off = 0x18; off < 0x800; off += 8) {
        uint64_t raw = kread64(gTask + off);
        if (raw == 0) continue;

        uint64_t forms[2] = { raw, xpaci(raw) };

        for (int k = 0; k < 2; k++) {
            uint64_t candidate = forms[k];
            if (candidate < gMapMin || candidate >= gMapMax) continue;
            if ((candidate & 0x7) != 0) continue;

            uint32_t count = 0;
            uint64_t array = 0;
            if (!kum_read_context(candidate + 4, &count, sizeof(count))) continue;
            if (count != expected) continue;
            if (!kum_read_context(candidate + 8, &array, sizeof(array))) continue;
            if (array < gMapMin || array >= gMapMax) continue;

            gInfoOffset = off;
            cyanide_log(@"[KUM] 校准成功：all_image_info_addr 在 task+0x%llx（自身模块数 %u）",
                        (unsigned long long)off, expected);
            return;
        }
    }

    cyanide_log(@"[KUM] 校准失败：自身 task 里没有与 _dyld_image_count()=%u 匹配的候选", expected);
}

// ---------------------------------------------------------------------------
// 对外接口
// ---------------------------------------------------------------------------

BOOL kum_prepare(uint64_t proc)
{
    if (!kexploit_krw_ready()) return NO;

    // 先用自己校准偏移（只需要做一次）。
    if (gInfoOffset == 0) {
        uint64_t me = proc_self();
        if (is_kaddr_valid(me) && kum_prepare_context(me)) {
            kum_calibrate();
        }
    }

    return kum_prepare_context(proc);
}

uint64_t kum_map_min(void) { return gMapMin; }
uint64_t kum_map_max(void) { return gMapMax; }

BOOL kum_read(uint64_t va, void *dst, size_t len)
{
    return kum_read_context(va, dst, len);
}

BOOL kum_main_executable_base(uint64_t *outBase)
{
    if (!gPrepared) return NO;

    // 主程序 __TEXT 一般在地址空间最低端，按页向下扫一段，用 Mach-O 头校验。
    uint64_t start = gMapMin & ~0xFFFULL;
    uint64_t limit = start + 0x40000;   // 最多找 256KB，避免无效长扫

    for (uint64_t va = start; va < limit; va += 0x1000) {
        uint32_t magic = 0;
        if (!kum_read_context(va, &magic, sizeof(magic))) continue;

        if (magic == 0xFEEDFACF || magic == 0xFEEDFACE || magic == 0xCAFEBABE) {
            if (outBase) *outBase = va;
            cyanide_log(@"[KUM] 主程序基址 0x%llx（Mach-O 头 0x%08x 校验通过）", va, magic);
            return YES;
        }
    }

    cyanide_log(@"[KUM] 主程序基址未找到（搜索区间 0x%llx - 0x%llx）", start, limit);
    return NO;
}

static BOOL kum_probe_all_image_infos(uint64_t va, uint32_t *outCount, uint64_t *outArray)
{
    uint32_t version = 0;
    uint32_t count = 0;
    uint64_t array = 0;

    if (!kum_read_context(va, &version, sizeof(version))) return NO;
    if (version < 1 || version > 64) return NO;

    if (!kum_read_context(va + 4, &count, sizeof(count))) return NO;
    if (count == 0 || count > 8192) return NO;

    if (!kum_read_context(va + 8, &array, sizeof(array))) return NO;
    if (array < gMapMin || array >= gMapMax) return NO;
    if ((array & 0x7) != 0) return NO;

    if (outCount) *outCount = count;
    if (outArray) *outArray = array;
    return YES;
}

NSArray<NSDictionary<NSString *, id> *> *kum_read_dyld_images(NSString **errorOut)
{
    if (!gPrepared) {
        if (errorOut) *errorOut = @"页表上下文未准备好";
        return nil;
    }

    if (gInfoOffset == 0) {
        if (errorOut) *errorOut = @"自身校准未成功，缺少 all_image_info 偏移";
        return nil;
    }

    uint64_t infoAddr = 0;
    uint32_t count = 0;
    uint64_t infoArray = 0;

    uint64_t raw = kread64(gTask + gInfoOffset);
    uint64_t forms[2] = { raw, xpaci(raw) };

    for (int k = 0; k < 2 && infoAddr == 0; k++) {
        uint64_t candidate = forms[k];
        if (candidate == 0) continue;
        if (candidate < gMapMin || candidate >= gMapMax) continue;
        if (kum_probe_all_image_infos(candidate, &count, &infoArray)) {
            infoAddr = candidate;
        }
    }

    if (infoAddr == 0) {
        if (errorOut) *errorOut = @"目标进程的 dyld_all_image_infos 校验未通过";
        return nil;
    }

    cyanide_log(@"[KUM] 目标 dyld_all_image_infos=0x%llx，%u 个模块", infoAddr, count);

    NSMutableArray<NSDictionary<NSString *, id> *> *rows =
        [NSMutableArray arrayWithCapacity:count];

    for (uint32_t i = 0; i < count; i++) {
        uint64_t entry = infoArray + (uint64_t)i * 24;

        uint64_t loadAddress = 0;
        uint64_t pathPtr = 0;
        if (!kum_read_context(entry, &loadAddress, sizeof(loadAddress))) continue;
        if (!kum_read_context(entry + 8, &pathPtr, sizeof(pathPtr))) continue;
        if (pathPtr == 0) continue;

        char pathBuffer[512] = {0};
        if (!kum_read_context(pathPtr, pathBuffer, sizeof(pathBuffer) - 1)) continue;

        NSString *path = [NSString stringWithUTF8String:pathBuffer];
        if (path.length == 0) path = @"";

        NSString *name = path.lastPathComponent;
        if (name.length == 0) name = path.length > 0 ? path : @"（未知）";

        [rows addObject:@{
            @"name": name,
            @"path": path,
            @"base": @(loadAddress),
        }];
    }

    if (rows.count == 0) {
        if (errorOut) *errorOut = @"dyld 列表读到了，但没有任何有效条目";
        return nil;
    }

    cyanide_log(@"[KUM] 成功读出 %lu 个模块（未附加、未建线程）", (unsigned long)rows.count);
    return rows;
}
