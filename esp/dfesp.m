//
//  dfesp.m
//  Injected dylib for Delta Force (UE4.22, iOS ARM64)
//
//  Runs INSIDE the game process, so every memory access is an ordinary
//  in-process dereference: no kernel R/W, no exception port hijack,
//  therefore no kernel panic and no risk of killing the game.
//
//  Build:  xcrun --sdk iphoneos clang -arch arm64e -dynamiclib ...
//  Install: inject with TrollFools (or repackage the IPA)
//
//  Output: /var/mobile/df_result.txt  + NSLog
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OUT_PATH        "/var/mobile/df_result.txt"
#define MOD_SIZE        0x16BFE1F0ULL
#define BSS_RVA         0x15D89B40ULL
#define BSS_SIZE        0x00A272F8ULL
#define COM_RVA         0x167B0E40ULL
#define COM_SIZE        0x002B43D0ULL
#define VT_LO_RVA       0x10B1F1C0ULL
#define VT_HI_RVA       0x15427A10ULL
#define MAX_OBJ         200000

static uint64_t gBase = 0, gModHi = 0, gVtLo = 0, gVtHi = 0;
static NSMutableString *gOut = nil;

// Safe read: returns NO for unmapped pages instead of faulting.
static BOOL rd(uint64_t addr, void *dst, size_t len)
{
    if (!addr || !dst || !len) return NO;
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                              (mach_vm_address_t)addr,
                                              (mach_vm_size_t)len,
                                              (mach_vm_address_t)dst,
                                              &out);
    return (kr == KERN_SUCCESS && out == len);
}

static uint64_t rd64(uint64_t a)
{
    uint64_t v = 0;
    if (!rd(a, &v, 8)) return 0;
    return v;
}

static uint32_t rd32(uint64_t a)
{
    uint32_t v = 0;
    if (!rd(a, &v, 4)) return 0;
    return v;
}

static BOOL isHeapPtr(uint64_t v)
{
    if (v < gModHi) return NO;           // must be above the module
    if (v >= 0x8000000000ULL) return NO;
    if (v & 7) return NO;
    return YES;
}

// A UE object starts with a vtable pointer that lives in the module's __const.
static BOOL isObject(uint64_t addr)
{
    uint64_t vt = rd64(addr);
    if (!vt) return NO;
    return (vt >= gVtLo && vt <= gVtHi);
}

// TArray { Data, Num, Max } at [addr + off]
static BOOL readTArray(uint64_t addr, uint64_t off,
                       uint64_t *data, uint32_t *num, uint32_t *max)
{
    uint64_t d = rd64(addr + off);
    uint32_t n = rd32(addr + off + 8);
    uint32_t m = rd32(addr + off + 0xC);
    if (!isHeapPtr(d)) return NO;
    if (n < 1 || n > 2000000) return NO;
    if (m < n || m > n * 2 + 4096) return NO;
    *data = d; *num = n; *max = m;
    return YES;
}

static uint64_t findBase(void)
{
    uint64_t h = (uint64_t)(uintptr_t)_dyld_get_image_header(0);
    if (!h) return 0;
    uint32_t mh[8] = {0};
    if (!rd(h, mh, sizeof(mh))) return 0;
    if (mh[0] != 0xFEEDFACF) return 0;
    return h;
}

static void logf_(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [gOut appendString:s];
    [gOut appendString:@"\n"];
    NSLog(@"[DFESP] %@", s);
}

static void run(void)
{
    gOut = [NSMutableString stringWithCapacity:65536];

    gBase = findBase();
    if (!gBase) {
        logf_(@"no base");
        goto done;
    }
    gModHi = gBase + MOD_SIZE;
    gVtLo  = gBase + VT_LO_RVA;
    gVtHi  = gBase + VT_HI_RVA;

    logf_(@"base   = 0x%llx", gBase);
    logf_(@"vtable = [0x%llx, 0x%llx]", gVtLo, gVtHi);

    // ---- read __bss + __common ----
    uint64_t total = BSS_SIZE + COM_SIZE;
    uint8_t *buf = (uint8_t *)malloc((size_t)total);
    if (!buf) { logf_(@"oom"); goto done; }
    memset(buf, 0, (size_t)total);

    const uint64_t PAGE = 0x4000;
    uint64_t off = 0, ok = 0;
    int fail = 0;
    while (off < total) {
        uint64_t n = total - off;
        if (n > PAGE) n = PAGE;
        uint64_t rva = (off < BSS_SIZE) ? (BSS_RVA + off)
                                        : (COM_RVA + (off - BSS_SIZE));
        if (rd(gBase + rva, buf + off, (size_t)n)) ok += n;
        else ++fail;
        off += n;
    }
    logf_(@"read %llu/%llu ok=%llu failpages=%d", off, total, ok, fail);

    // ---- collect global slots holding heap pointers ----
    size_t nslots = (size_t)(off / 8);
    uint64_t *slots = (uint64_t *)malloc(nslots * 8);
    size_t ns = 0;
    for (size_t i = 0; i < nslots; i++) {
        uint64_t v;
        memcpy(&v, buf + i * 8, 8);
        if (isHeapPtr(v)) slots[ns++] = v;
    }
    logf_(@"heap-pointer slots = %zu", ns);

    // ---- vtable-verify each slot's target; keep real objects ----
    uint64_t *objs = (uint64_t *)malloc(MAX_OBJ * 8);
    size_t no = 0;
    size_t limit = ns < 40000 ? ns : 40000;
    for (size_t i = 0; i < limit && no < MAX_OBJ; i++) {
        uint64_t c = slots[i];
        if (!isObject(c)) continue;
        // dedupe cheaply
        BOOL dup = NO;
        for (size_t k = 0; k < no; k++) if (objs[k] == c) { dup = YES; break; }
        if (!dup) objs[no++] = c;
    }
    logf_(@"verified UObjects = %zu", no);

    // ---- find UWorld: some offset holds a TArray of objects,
    //      and the first element has an Actors TArray at +0x28 ----
    uint64_t world = 0, levelsData = 0, levelsOff = 0;
    uint32_t levelsNum = 0;

    for (size_t i = 0; i < no && !world; i++) {
        uint64_t cand = objs[i];
        for (uint64_t o = 0x08; o <= 0x300; o += 8) {
            uint64_t d; uint32_t n, m;
            if (!readTArray(cand, o, &d, &n, &m)) continue;
            if (n > 100000) continue;

            uint64_t lv = rd64(d);
            if (!isHeapPtr(lv)) continue;
            if (!isObject(lv)) continue;

            uint64_t act; uint32_t an, am;
            if (!readTArray(lv, 0x28, &act, &an, &am)) continue;
            if (an > 200000) continue;

            uint64_t a0 = rd64(act);
            if (!isHeapPtr(a0)) continue;

            world = cand; levelsData = d; levelsOff = o; levelsNum = n;
            logf_(@"WORLD 0x%llx  levels@+0x%llx n=%u  level0=0x%llx actors=0x%llx an=%u",
                  world, o, n, lv, act, an);
            break;
        }
    }

    if (!world) {
        logf_(@"no UWorld found among %zu objects", no);
        goto done;
    }

    // ---- locate the global slot that holds this UWorld = GWorld ----
    for (size_t i = 0; i < nslots; i++) {
        uint64_t v;
        memcpy(&v, buf + i * 8, 8);
        if (v != world) continue;
        uint64_t rva = (i * 8 < BSS_SIZE) ? (BSS_RVA + i * 8)
                                          : (COM_RVA + (i * 8 - BSS_SIZE));
        logf_(@"GWORLD_SLOT = base + 0x%llx", rva);
    }

    // ---- dump the level and its actors ----
    {
        uint64_t lv = rd64(levelsData);
        uint64_t act; uint32_t an, am;
        if (readTArray(lv, 0x28, &act, &an, &am)) {
            logf_(@"ULevel 0x%llx  Actors 0x%llx  count=%u", lv, act, an);
            uint32_t k, shown = an < 16 ? an : 16;
            for (k = 0; k < shown; k++) {
                uint64_t a = rd64(act + (uint64_t)k * 8);
                logf_(@"  actor[%u] = 0x%llx", k, a);
            }
        }

        uint8_t lvbuf[0x200];
        if (rd(lv, lvbuf, sizeof(lvbuf))) {
            logf_(@"ULevel raw 0x200:");
            for (int r = 0; r < 0x200; r += 16) {
                NSMutableString *line = [NSMutableString stringWithFormat:@"%03X ", r];
                for (int j = 0; j < 16; j++)
                    [line appendFormat:@"%02X", lvbuf[r + j]];
                logf_(@"%@", line);
            }
        }
    }

done:
    [gOut writeToFile:@OUT_PATH atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"[DFESP] done -> %s", OUT_PATH);
}

__attribute__((constructor))
static void dfesp_boot(void)
{
    // Wait for the engine and the first level to finish loading.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        run();
    });
}
