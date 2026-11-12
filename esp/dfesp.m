//
//  dfesp.m
//  Injected dylib for Delta Force (UE4.22, iOS ARM64)
//
//  Runs INSIDE the game process, so every memory access is an ordinary
//  in-process dereference: no kernel R/W, no exception port hijack,
//  therefore no kernel panic and no risk of killing the game.
//
//  Build:   make -C esp          (xcrun iphoneos clang -dynamiclib)
//  Install: Sideloadly "Inject dylib", or TrollFools
//
//  Output: the result is shown in an alert inside the game and copied to the
//  pasteboard, because a sideloaded (sandboxed) app cannot write /var/mobile.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/mach_types.h>
#import <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// <mach/mach_vm.h> is marked unsupported in the iOS SDK; declare the
// (stable, exported) symbol directly.
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *outsize);

#define MOD_SIZE        0x16BFE1F0ULL
#define BSS_RVA         0x15D89B40ULL
#define BSS_SIZE        0x00A272F8ULL
#define COM_RVA         0x167B0E40ULL
#define COM_SIZE        0x002B43D0ULL
#define VT_LO_RVA       0x10B1F1C0ULL
#define VT_HI_RVA       0x15427A10ULL
#define MAX_OBJ         300000

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
    if (v < gModHi) return NO;
    if (v >= 0x8000000000ULL) return NO;
    if (v & 7) return NO;
    return YES;
}

// A UE object starts with a vtable pointer living in the module's __const.
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

static void say(NSString *fmt, ...)
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
    gOut = [NSMutableString stringWithCapacity:16384];

    uint64_t hdr = (uint64_t)(uintptr_t)_dyld_get_image_header(0);
    if (!hdr) { say(@"no image header"); return; }

    uint32_t mh[8] = {0};
    if (!rd(hdr, mh, sizeof(mh))) { say(@"cannot read header"); return; }

    gBase  = hdr;
    gModHi = hdr + MOD_SIZE;
    gVtLo  = hdr + VT_LO_RVA;
    gVtHi  = hdr + VT_HI_RVA;

    say(@"base   0x%llx  magic=0x%08x ncmds=%u", hdr, mh[0], mh[4]);
    say(@"vtable [0x%llx, 0x%llx]", gVtLo, gVtHi);

    // ---- read __bss + __common ----
    uint64_t total = BSS_SIZE + COM_SIZE;
    uint8_t *buf = (uint8_t *)malloc((size_t)total);
    if (!buf) { say(@"oom"); return; }
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
    say(@"read ok=%llu/%llu failpages=%d", ok, total, fail);

    size_t nslots = (size_t)(off / 8);
    uint64_t *slots = (uint64_t *)malloc(nslots * 8);
    if (!slots) { say(@"oom2"); free(buf); return; }
    size_t ns = 0;
    for (size_t i = 0; i < nslots; i++) {
        uint64_t v;
        memcpy(&v, buf + i * 8, 8);
        if (isHeapPtr(v)) slots[ns++] = v;
    }
    say(@"heap slots = %zu", ns);

    // ---- verified UObjects ----
    uint64_t *objs = (uint64_t *)malloc(MAX_OBJ * 8);
    size_t no = 0;
    size_t limit = ns < 60000 ? ns : 60000;
    for (size_t i = 0; i < limit && no < MAX_OBJ; i++) {
        uint64_t c = slots[i];
        if (!isObject(c)) continue;
        BOOL dup = NO;
        for (size_t k = 0; k < no; k++) if (objs[k] == c) { dup = YES; break; }
        if (!dup) objs[no++] = c;
    }
    say(@"UObjects = %zu", no);

    // ---- find UWorld ----
    uint64_t world = 0, levelsData = 0;
    for (size_t i = 0; i < no && !world; i++) {
        uint64_t cand = objs[i];
        for (uint64_t o = 0x08; o <= 0x300; o += 8) {
            uint64_t d; uint32_t n, m;
            if (!readTArray(cand, o, &d, &n, &m)) continue;
            if (n > 100000) continue;
            uint64_t lv = rd64(d);
            if (!isHeapPtr(lv) || !isObject(lv)) continue;
            uint64_t act; uint32_t an, am;
            if (!readTArray(lv, 0x28, &act, &an, &am)) continue;
            uint64_t a0 = rd64(act);
            if (!isHeapPtr(a0)) continue;

            world = cand; levelsData = d;
            say(@"WORLD 0x%llx levels@+0x%llx n=%u level0=0x%llx actors=0x%llx an=%u",
                world, o, n, lv, act, an);
            break;
        }
    }

    if (!world) {
        say(@"NO UWorld among %zu objects", no);
        free(objs); free(slots); free(buf);
        return;
    }

    // ---- global slot holding this UWorld = GWorld ----
    for (size_t i = 0; i < nslots; i++) {
        uint64_t v;
        memcpy(&v, buf + i * 8, 8);
        if (v != world) continue;
        uint64_t rva = (i * 8 < BSS_SIZE) ? (BSS_RVA + i * 8)
                                          : (COM_RVA + (i * 8 - BSS_SIZE));
        say(@"GWORLD_SLOT = base + 0x%llx", rva);
    }

    // ---- level + actors ----
    {
        uint64_t lv = rd64(levelsData);
        uint64_t act; uint32_t an, am;
        if (readTArray(lv, 0x28, &act, &an, &am)) {
            say(@"ULevel 0x%llx Actors 0x%llx n=%u", lv, act, an);
            uint32_t shown = an < 12 ? an : 12;
            for (uint32_t k = 0; k < shown; k++)
                say(@"  actor[%u]=0x%llx", k, rd64(act + (uint64_t)k * 8));
        } else {
            say(@"level actors unreadable");
        }
    }

    free(objs); free(slots); free(buf);
}

static void present(void)
{
    // Sandboxed app -> cannot write /var/mobile. Show it in-app instead.
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [gOut writeToFile:[docs stringByAppendingPathComponent:@"df_result.txt"]
           atomically:YES encoding:NSUTF8StringEncoding error:nil];

    [UIPasteboard generalPasteboard].string = gOut;

    UIWindow *key = nil;
    for (UIWindow *w in [UIApplication sharedApplication].windows)
        if (w.isKeyWindow) { key = w; break; }
    if (!key) key = [UIApplication sharedApplication].windows.firstObject;

    UIViewController *root = key.rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    if (!root) return;

    UIAlertController *a =
        [UIAlertController alertControllerWithTitle:@"DFESP result"
                                            message:gOut
                                     preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK"
                                          style:UIAlertActionStyleDefault
                                        handler:nil]];
    [root presentViewController:a animated:YES completion:nil];
}

__attribute__((constructor))
static void dfesp_boot(void)
{
    // Let the engine boot and load the first level.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(25 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        run();
        dispatch_async(dispatch_get_main_queue(), ^{
            present();
        });
    });
}
