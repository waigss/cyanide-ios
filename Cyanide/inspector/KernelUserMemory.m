//
//  KernelUserMemory.m
//  Cyanide
//
//  实现见头文件说明。所有地址都先过页表校验，未映射的地址直接返回 NO，
//  不会触发内核异常（之前闪退就是因为直接读了一个未映射地址）。
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

// 16KB 页、3 级页表
static const uint64_t kPageSize      = 0x4000ULL;
static const uint64_t kPageMask      = 0x3FFFULL;
static const uint64_t kPaMask        = 0x0000FFFFFFFFC000ULL;  // 页表项里的物理地址：bit[47:14]
static const unsigned int kL0Shift   = 36;
static const unsigned int kL1Shift   = 25;
static const unsigned int kL2Shift   = 14;
static const uint64_t kL0IndexMask   = 0xFFFULL;
static const uint64_t kL1IndexMask   = 0x7FFULL;
static const uint64_t kL2IndexMask   = 0x7FFULL;

// _vm_map.pmap 的偏移（对照 xnu-11417 的 struct _vm_map 布局得出，已在 iOS 18.5 实测验证）
static const uint64_t kPmapOffsetInVmMap = 0x40;

static uint64_t gPmap = 0;
static uint64_t gRootTable = 0;       // tte：根页表的内核虚拟地址
static uint64_t gWindowOffset = 0;    // tte - ttep：物理地址 → 内核虚拟地址的线性偏移
static uint64_t gMapMin = 0;
static uint64_t gMapMax = 0;
static uint64_t gTask = 0;

static BOOL gPrepared = NO;

BOOL kum_prepare(uint64_t proc)
{
    gPrepared = NO;
    gPmap = 0;
    gRootTable = 0;
    gWindowOffset = 0;
    gMapMin = 0;
    gMapMax = 0;
    gTask = 0;

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

uint64_t kum_map_min(void) { return gMapMin; }
uint64_t kum_map_max(void) { return gMapMax; }

// 把当前页表上下文里的一段物理页映射成可读内核地址；失败返回 0。
static uint64_t kum_kva_for_page(uint64_t va, uint64_t *outAvail)
{
    if (!gPrepared) return 0;

    uint64_t l0Index = (va >> kL0Shift) & kL0IndexMask;
    uint64_t e0 = kread64(gRootTable + l0Index * 8);
    if ((e0 & 1) == 0) return 0;

    uint64_t l1Kva = (e0 & kPaMask) + gWindowOffset;
    uint64_t l1Index = (va >> kL1Shift) & kL1IndexMask;
    uint64_t e1 = kread64(l1Kva + l1Index * 8);
    if ((e1 & 1) == 0) return 0;

    // bit1 = 0 表示块映射（大页），这里按 16KB 页处理，遇到块直接放弃
    if ((e1 & 2) == 0) return 0;

    uint64_t l2Kva = (e1 & kPaMask) + gWindowOffset;
    uint64_t l2Index = (va >> kL2Shift) & kL2IndexMask;
    uint64_t e2 = kread64(l2Kva + l2Index * 8);
    if ((e2 & 1) == 0) return 0;
    if ((e2 & 2) == 0) return 0;

    uint64_t pagePa = e2 & kPaMask;
    if (outAvail) {
        uint64_t inPage = va & kPageMask;
        *outAvail = kPageSize - inPage;
    }
    return pagePa + gWindowOffset;
}

BOOL kum_read(uint64_t va, void *dst, size_t len)
{
    if (!gPrepared || !dst || len == 0) return NO;
    if (va < gMapMin || va + len > gMapMax) return NO;

    uint8_t *out = (uint8_t *)dst;
    size_t remaining = len;
    uint64_t cursor = va;

    while (remaining > 0) {
        uint64_t avail = 0;
        uint64_t kva = kum_kva_for_page(cursor, &avail);
        if (kva == 0 || avail == 0) return NO;

        uint64_t inPage = cursor & kPageMask;
        size_t chunk = (size_t)((remaining < avail) ? remaining : avail);

        kreadbuf(kva + inPage, out, (uint64_t)chunk);

        out += chunk;
        cursor += chunk;
        remaining -= chunk;
    }

    return YES;
}

static BOOL kum_read_u32(uint64_t va, uint32_t *value)
{
    return kum_read(va, value, sizeof(*value));
}

static BOOL kum_read_u64(uint64_t va, uint64_t *value)
{
    return kum_read(va, value, sizeof(*value));
}

// dyld_all_image_infos 的形态校验：
//   +0x00 uint32 version（1..8）
//   +0x04 uint32 infoArrayCount（1..4096）
//   +0x08 uint64 infoArray（落在目标地址空间内）
static BOOL kum_probe_all_image_infos(uint64_t va, uint32_t *outCount, uint64_t *outArray)
{
    uint32_t version = 0;
    uint32_t count = 0;
    uint64_t array = 0;

    if (!kum_read_u32(va, &version)) return NO;
    if (version < 1 || version > 8) return NO;

    if (!kum_read_u32(va + 4, &count)) return NO;
    if (count == 0 || count > 4096) return NO;

    if (!kum_read_u64(va + 8, &array)) return NO;
    if (array < gMapMin || array >= gMapMax) return NO;
    if ((array & 0x7) != 0) return NO;

    if (outCount) *outCount = count;
    if (outArray) *outArray = array;
    return YES;
}

// 在 task 结构里找 all_image_info_addr。
// 注意：这个字段是「用户态地址」，必须用 kread64 原样读；
// 用 kread_ptr（内部 xpaci）会把用户指针弄坏。为兼容 PAC 签名的情况，
// 每个字段同时尝试「原始值」和「xpaci 后的值」两种形态。
static uint64_t kum_find_all_image_info(uint64_t *outCount, uint64_t *outArray,
                                        uint64_t *outOffset)
{
    uint64_t inRange = 0;
    uint64_t probed = 0;

    for (uint64_t off = 0x18; off < 0x800; off += 8) {
        uint64_t raw = kread64(gTask + off);
        if (raw == 0) continue;

        uint64_t forms[2];
        forms[0] = raw;
        forms[1] = xpaci(raw);

        for (int k = 0; k < 2; k++) {
            uint64_t candidate = forms[k];
            if (candidate == 0) continue;
            if (candidate < gMapMin || candidate >= gMapMax) continue;
            if ((candidate & 0x7) != 0) continue;

            inRange += 1;

            uint32_t count = 0;
            uint64_t array = 0;
            probed += 1;
            if (!kum_probe_all_image_infos(candidate, &count, &array)) continue;

            if (outCount) *outCount = count;
            if (outArray) *outArray = array;
            if (outOffset) *outOffset = off;
            return candidate;
        }
    }

    cyanide_log(@"[KUM] task 扫描结束：落在地址空间内的候选 %llu 个，形态校验全部未通过",
                (unsigned long long)inRange);
    return 0;
}

NSArray<NSDictionary<NSString *, id> *> *kum_read_dyld_images(NSString **errorOut)
{
    if (!gPrepared) {
        if (errorOut) *errorOut = @"页表上下文未准备好";
        return nil;
    }

    uint32_t count = 0;
    uint64_t infoArray = 0;

    uint64_t infoOffset = 0;
    cyanide_log(@"[KUM] 目标地址空间 0x%llx - 0x%llx", gMapMin, gMapMax);

    uint64_t found = kum_find_all_image_info(&count, &infoArray, &infoOffset);
    if (found == 0) {
        if (errorOut) *errorOut = @"没有在 task 里找到 dyld_all_image_infos";
        return nil;
    }

    cyanide_log(@"[KUM] 找到 dyld_all_image_infos：task+0x%llx -> 0x%llx，共 %u 个模块",
                (unsigned long long)infoOffset, found, count);

    NSMutableArray<NSDictionary<NSString *, id> *> *rows =
        [NSMutableArray arrayWithCapacity:count];

    for (uint32_t i = 0; i < count; i++) {
        uint64_t entry = infoArray + (uint64_t)i * 24;

        uint64_t loadAddress = 0;
        uint64_t pathPtr = 0;
        if (!kum_read_u64(entry, &loadAddress)) continue;
        if (!kum_read_u64(entry + 8, &pathPtr)) continue;
        if (pathPtr == 0) continue;

        char pathBuffer[512] = {0};
        if (!kum_read(pathPtr, pathBuffer, sizeof(pathBuffer) - 1)) continue;

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

    return rows;
}
