//
//  AppDelegate.m
//  Cyanide
//
//  Created by seo on 3/24/26.
//

#import "AppDelegate.h"
#import "SettingsViewController.h"
#import "DSKeepAlive.h"
#import "LogTextView.h"
#import "inspector/CyanideLog.h"
#import "inspector/KernelUserMemory.h"
#import "kexploit/kutils.h"
#import "kexploit/krw.h"
#import <signal.h>
#import <sys/stat.h>
#import <unistd.h>
#include <stdlib.h>
#include <string.h>

// ===========================================================================
//  Delta Force (UE4.22, iOS ARM64) memory scan
//
//  Uses KernelUserMemory (kernel page-table translation) instead of
//  RemoteCall: no attach, no remote threads, no exception ports.
//
//  RVAs come from static analysis of the Mach-O binary and are relative to
//  the __TEXT start (vmaddr 0x100000000), i.e. kum_main_executable_base().
//
//    __bss       RVA 0x15D89B40   size 0x0A272F8
//    __common    RVA 0x167B0E40   size 0x02B43D0
//
//  Chain we try to recover:
//    GWorld -> UWorld -> Levels -> ULevel -> Actors -> AActor[]
//
//    UWorld::Levels candidate offsets: +0x28 or +0x158
//        TArray { Data @ +0x00, Num @ +0x08, Max @ +0x0C }
//    ULevel::Actors  offset +0x28
//        TArray { Data @ +0x00, Num @ +0x08, Max @ +0x0C }
// ===========================================================================

// Scan window: __bss + __common only.
//   __bss     RVA 0x15D89B40  size 0x0A272F8
//   __common  RVA 0x167B0E40  size 0x02B43D0
//
// __data is deliberately excluded: it holds megabytes of float/int constants
// that pass a naive "looks like a pointer" test, and dereferencing those bogus
// addresses walks bogus page-table chains, which panics the kernel.
#define DF_SCAN_RVA   0x15D89B40ULL
#define DF_SCAN_END   (0x167B0E40ULL + 0x02B43D0ULL)
#define DF_SCAN_SIZE  (DF_SCAN_END - DF_SCAN_RVA)

#define DF_BSS_RVA   0x15D89B40ULL
#define DF_COM_RVA   0x167B0E40ULL
#define DF_MOD_SIZE  0x16BFE1F0ULL

static uint64_t g_dfSlide = 0;

static inline uint64_t dfVa(uint64_t rva) { return g_dfSlide + rva; }

static uint64_t dfRd64(uint64_t a)
{
    uint64_t v = 0;
    if (!kum_read(a, &v, 8)) return 0;
    return v;
}

static uint32_t dfRd32(uint64_t a)
{
    uint32_t v = 0;
    if (!kum_read(a, &v, 4)) return 0;
    return v;
}

static int dfPlausiblePtr(uint64_t p)
{
    if (p < 0x100000000ULL)   return 0;
    if (p >= 0x8000000000ULL) return 0;
    if (p & 7)                return 0;
    // Reject pointers into the game module itself: those are vtables / const
    // data / string literals, never heap objects (UWorld / ULevel / AActor).
    if (g_dfSlide && p >= g_dfSlide && p < g_dfSlide + DF_MOD_SIZE) return 0;
    return 1;
}

static int dfCmpU64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

// Local (already-read) variant: parse a TArray out of an in-memory block.
static int dfParseTArray(const uint8_t *blk, int off,
                         uint64_t *outData, uint32_t *outNum)
{
    uint64_t data;
    uint32_t num, max;
    memcpy(&data, blk + off, 8);
    memcpy(&num,  blk + off + 8, 4);
    memcpy(&max,  blk + off + 0xC, 4);
    if (!dfPlausiblePtr(data)) return 0;
    if (num < 1 || num > 200000) return 0;
    if (max < num || max > num * 2 + 1024) return 0;
    *outData = data;
    *outNum  = num;
    return 1;
}

// Local variant of the ULevel::Actors check.
static int dfParseLevel(const uint8_t *blk,
                        uint64_t *outActors, uint32_t *outNum)
{
    uint64_t act;
    uint32_t num, max;
    memcpy(&act, blk + 0x28, 8);
    memcpy(&num, blk + 0x30, 4);
    memcpy(&max, blk + 0x34, 4);
    if (!dfPlausiblePtr(act)) return 0;
    if (num < 1 || num > 200000) return 0;
    if (max < num || max > num * 2 + 1024) return 0;
    *outActors = act;
    *outNum    = num;
    return 1;
}

// Returns 1 when [level + 0x28] looks like ULevel::Actors.
static int dfLooksLikeLevel(uint64_t level,
                            uint64_t *outActors, uint32_t *outNum)
{
    if (!dfPlausiblePtr(level)) return 0;
    uint64_t data = dfRd64(level + 0x28);
    uint32_t num  = dfRd32(level + 0x30);
    uint32_t max  = dfRd32(level + 0x34);
    if (!dfPlausiblePtr(data)) return 0;
    if (num < 1 || num > 200000) return 0;
    if (max < num || max > num * 2 + 1024) return 0;

    uint64_t a0 = dfRd64(data);
    if (!dfPlausiblePtr(a0)) return 0;

    *outActors = data;
    *outNum    = num;
    return 1;
}

// Blocking. Returns the report text.
NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:16384];
    cyanide_log(@"[DF] ===== scan begin =====");

    if (!settings_ensure_kernel_ready()) {
        cyanide_log(@"[DF] kernel r/w not ready");
        return @"kernel r/w not ready";
    }
    cyanide_log(@"[DF] kernel ready");

    // ---- enumerate the kernel proc list ----
    static proc_entry_t ents[512];
    int n = proc_list_all(ents, 512);
    cyanide_log(@"[DF] proc_list_all -> %d", n);
    [out appendFormat:@"proc_list_all = %d\n", n];
    if (n <= 0) {
        [out appendString:@"cannot read kernel proc list\n"];
        return out;
    }

    uint64_t targetProc = 0;
    int targetPid = 0;
    char targetName[PROC_NAME_MAX];
    memset(targetName, 0, sizeof(targetName));

    for (int i = 0; i < n; i++) {
        const char *nm = ents[i].name;
        [out appendFormat:@"  pid=%-6u %-22s proc=0x%llx\n",
                          ents[i].pid, nm, ents[i].proc];

        char low[PROC_NAME_MAX];
        int j = 0;
        for (; nm[j] && j < PROC_NAME_MAX - 1; j++) {
            char c = nm[j];
            low[j] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        low[j] = 0;

        if (!targetProc &&
            (strstr(low, "delta") || strstr(low, "dfm") || strstr(low, "tmgp"))) {
            targetProc = ents[i].proc;
            targetPid  = (int)ents[i].pid;
            strncpy(targetName, nm, PROC_NAME_MAX - 1);
        }
    }

    if (!targetProc) {
        cyanide_log(@"[DF] no Delta-like process found");
        [out appendString:@"\nNO DELTA PROCESS FOUND\n"];
        return out;
    }

    cyanide_log(@"[DF] target %s pid=%d proc=0x%llx", targetName, targetPid, targetProc);
    [out appendFormat:@"\ntarget = %s  pid=%d  proc=0x%llx\n", targetName, targetPid, targetProc];

    // ---- prepare kernel page-table context for that process ----
    if (!kum_prepare(targetProc)) {
        cyanide_log(@"[DF] kum_prepare failed");
        [out appendString:@"kum_prepare FAILED\n"];
        return out;
    }
    cyanide_log(@"[DF] kum_prepare ok  map=[0x%llx,0x%llx]",
                kum_map_min(), kum_map_max());
    [out appendFormat:@"map = [0x%llx, 0x%llx]\n", kum_map_min(), kum_map_max()];

    uint64_t base = 0;
    if (!kum_main_executable_base(&base) || base < 0x100000000ULL) {
        cyanide_log(@"[DF] cannot locate main executable");
        [out appendString:@"cannot locate main executable\n"];
        return out;
    }
    g_dfSlide = base;
    cyanide_log(@"[DF] base = 0x%llx", base);
    [out appendFormat:@"base   = 0x%llx\n", base];

    // Sanity-check the Mach-O header we just located.
    {
        uint32_t mh[8] = {0};
        if (kum_read(base, mh, sizeof(mh))) {
            cyanide_log(@"[DF] macho magic=0x%08x cputype=0x%08x filetype=%u ncmds=%u",
                        mh[0], mh[1], mh[3], mh[4]);
            [out appendFormat:@"macho  magic=0x%08x cputype=0x%08x filetype=%u ncmds=%u\n",
                              mh[0], mh[1], mh[3], mh[4]];
        }
    }
    [out appendFormat:@"scan   = [0x%llx .. 0x%llx]  (%llu bytes)\n\n",
                      dfVa(DF_SCAN_RVA), dfVa(DF_SCAN_END), DF_SCAN_SIZE];

    // ---- read __bss + __common ----
    uint64_t total = DF_SCAN_SIZE;
    uint8_t *buf = (uint8_t *)malloc((size_t)total);
    if (!buf) {
        [out appendString:@"malloc failed\n"];
        return out;
    }
    memset(buf, 0, (size_t)total);

    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    // __bss is zero-fill: untouched pages have no page-table entry, so a big
    // read fails as soon as it crosses one. Read one page at a time and just
    // leave zeros for unmapped pages.
    const uint64_t PAGE = 0x4000;
    uint64_t off = 0;
    int failPages = 0;
    uint64_t okBytes = 0;
    uint64_t nextLog = 0x400000;
    while (off < total) {
        uint64_t chunk = total - off;
        if (chunk > PAGE) chunk = PAGE;
        // keep page-aligned so we never straddle two mappings
        uint64_t rva = DF_SCAN_RVA + off;
        if (kum_read(dfVa(rva), buf + off, (size_t)chunk)) {
            okBytes += chunk;
        } else {
            ++failPages;
        }
        off += chunk;
        if (off >= nextLog) {
            cyanide_log_sync(@"[DF] read %llu / %llu (ok=%llu failpages=%d)",
                             off, total, okBytes, failPages);
            nextLog += 0x400000;
        }
    }
    double ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0;
    cyanide_log(@"[DF] read done %llu/%llu ok=%llu failPages=%d %.0fms",
                off, total, okBytes, failPages, ms);
    [out appendFormat:@"read %llu/%llu bytes (ok=%llu, unmapped pages=%d) in %.0f ms\n\n",
                      off, total, okBytes, failPages, ms];

    // ---- collect plausible object pointers ----
    const size_t MAXC = 400000;
    uint64_t *cands = (uint64_t *)malloc(sizeof(uint64_t) * MAXC);
    if (!cands) {
        free(buf);
        [out appendString:@"cand alloc failed\n"];
        return out;
    }
    size_t nc = 0;
    uint64_t modLo = g_dfSlide;
    uint64_t modHi = g_dfSlide + DF_MOD_SIZE;

    for (uint64_t o = 0; o + 8 <= off; o += 8) {
        uint64_t v;
        memcpy(&v, buf + o, 8);
        if (v < 0x100000000ULL || v >= 0x8000000000ULL) continue;
        if (v >= modLo && v < modHi) continue;
        if (v & 7) continue;
        if (nc < MAXC) cands[nc++] = v;
    }
    cyanide_log(@"[DF] raw candidates = %zu", nc);

    qsort(cands, nc, sizeof(uint64_t), dfCmpU64);

    // Keep only values referenced from >= 2 different slots. Real object
    // pointers show up repeatedly; float/int constants that merely look like
    // pointers usually appear once. Every dereference walks page tables inside
    // the kernel, so cutting the candidate count also cuts panic surface.
    size_t nu = 0;
    for (size_t i = 0; i < nc; ) {
        size_t j = i;
        while (j < nc && cands[j] == cands[i]) j++;
        if ((j - i) >= 2 && nu < MAXC) cands[nu++] = cands[i];
        i = j;
    }
    cyanide_log_sync(@"[DF] candidates with >=2 refs = %zu (raw %zu)", nu, nc);
    [out appendFormat:@"candidates (>=2 refs) = %zu  (raw %zu)\n\n", nu, nc];

    // ---- probe ----
    // One kum_read per candidate covers offsets 0x08..0x180 (enough for both
    // the +0x28 and the +0x158 Levels candidates), so the expensive page-table
    // walk runs once instead of ~100 times.
    static int offHits[64];
    memset(offHits, 0, sizeof(offHits));
    uint64_t bestWorld = 0, bestLevels = 0, bestOff = 0;
    int chainHits = 0, arrHits = 0;

    static uint8_t wbuf[0x190];
    static uint8_t lbuf[0x60];

    const int OFF_START = 0x08;
    const int OFF_END   = 0x180;
    size_t probeLimit = nu < 1500 ? nu : 1500;

    for (size_t i = 0; i < probeLimit; i++) {
        if ((i % 100) == 0)
            cyanide_log_sync(@"[DF] probe %zu / %zu  cur=0x%llx",
                             i, probeLimit, cands[i]);
        uint64_t c = cands[i];
        if (!kum_read(c, wbuf, sizeof(wbuf))) continue;

        for (int off = OFF_START; off <= OFF_END; off += 8) {
            uint64_t data; uint32_t num;
            if (!dfParseTArray(wbuf, off, &data, &num)) continue;
            ++arrHits;
            offHits[(off - 0x08) / 8]++;

            // first element should be a ULevel*
            uint64_t lv = 0;
            if (!kum_read(data, &lv, 8)) continue;
            if (!dfPlausiblePtr(lv)) continue;

            if (!kum_read(lv, lbuf, sizeof(lbuf))) continue;
            uint64_t act; uint32_t an;
            if (!dfParseLevel(lbuf, &act, &an)) continue;

            // Actors[0] must itself be a pointer
            uint64_t a0 = 0;
            if (!kum_read(act, &a0, 8)) continue;
            if (!dfPlausiblePtr(a0)) continue;

            ++chainHits;
            cyanide_log(@"[DF] CHAIN world=0x%llx levelsOff=0x%x n=%u "
                        @"level0=0x%llx actors=0x%llx an=%u a0=0x%llx",
                        c, off, num, lv, act, an, a0);
            [out appendFormat:@"CHAIN world=0x%llx levelsOff=0x%x n=%u "
                              @"level0=0x%llx actors=0x%llx an=%u a0=0x%llx\n",
                              c, off, num, lv, act, an, a0];
            if (!bestWorld) {
                bestWorld = c; bestLevels = data; bestOff = (uint64_t)off;
            }
        }
    }

    cyanide_log(@"[DF] tarray hits=%d chain hits=%d", arrHits, chainHits);
    [out appendFormat:@"\ntarray matches=%d  full-chain matches=%d\n",
                      arrHits, chainHits];

    // offset histogram: the real UWorld::Levels offset will dominate
    [out appendString:@"\noffset histogram (top 12):\n"];
    for (int n2 = 0; n2 < 12; n2++) {
        int bestIdx = -1, bestVal = 0;
        for (int k = 0; k < 64; k++) {
            if (offHits[k] > bestVal) { bestVal = offHits[k]; bestIdx = k; }
        }
        if (bestIdx < 0) break;
        [out appendFormat:@"  +0x%03X  x%d\n", OFF_START + bestIdx * 8, bestVal];
        offHits[bestIdx] = 0;
    }

    // ---- find the global slot holding this UWorld (= GWorld) ----
    if (bestWorld) {
        [out appendFormat:@"best world = 0x%llx (levels at +0x%llx)\n",
                          bestWorld, bestOff];
        for (uint64_t o = 0; o + 8 <= off; o += 8) {
            uint64_t v;
            memcpy(&v, buf + o, 8);
            if (v != bestWorld) continue;
            uint64_t slotRva = DF_SCAN_RVA + o;
            cyanide_log(@"[DF] >>> GWORLD SLOT base+0x%llx = 0x%llx", slotRva, v);
            [out appendFormat:@"GWORLD_SLOT = base + 0x%llx\n", slotRva];
        }

        uint64_t lv = dfRd64(bestLevels);
        uint64_t act = 0; uint32_t an = 0;
        if (dfLooksLikeLevel(lv, &act, &an)) {
            cyanide_log(@"[DF] LEVEL0=0x%llx actors=0x%llx n=%u", lv, act, an);
            [out appendFormat:@"\nULevel = 0x%llx\nActors = 0x%llx  count = %u\n",
                              lv, act, an];
            for (uint32_t k = 0; k < an && k < 12; k++) {
                uint64_t a = dfRd64(act + (uint64_t)k * 8);
                cyanide_log(@"[DF]   actor[%u]=0x%llx", k, a);
                [out appendFormat:@"  actor[%u] = 0x%llx\n", k, a];
            }

            uint8_t lvbuf[0x200];
            if (kum_read(lv, lvbuf, sizeof(lvbuf))) {
                [out appendString:@"\nULevel raw 0x200:\n"];
                for (int row = 0; row < 0x200; row += 16) {
                    [out appendFormat:@"%03X ", row];
                    for (int j = 0; j < 16; j++)
                        [out appendFormat:@"%02X", lvbuf[row + j]];
                    [out appendString:@"\n"];
                }
            }
        }
    } else {
        [out appendString:@"\nNO WORLD CANDIDATE FOUND\n"];
    }

    free(cands);
    free(buf);
    cyanide_log(@"[DF] ===== scan done =====");
    return out;
}

// Blocking wrapper: also writes Documents/df_result.txt.
void df_scan_run(void)
{
    NSString *r = df_scan_collect();
    if (!r) return;
    NSString *path = [NSHomeDirectory()
                      stringByAppendingPathComponent:@"Documents/df_result.txt"];
    NSError *err = nil;
    BOOL ok = [r writeToFile:path atomically:YES
                    encoding:NSUTF8StringEncoding error:&err];
    cyanide_log(@"[DF] report -> %@ (%@)", path, ok ? @"ok" : @"FAIL");
}

@interface AppDelegate ()

@end

static dispatch_source_t g_sigterm_source;

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [self logBootIdentity];
    settings_register_defaults();
    log_set_verbose(YES);
    ds_keepalive_apply_enabled([[NSUserDefaults standardUserDefaults] boolForKey:kSettingsKeepAlive]);
    [self installTerminationHandlers];
    [self installBarAppearances];
    return YES;
}

- (void)logBootIdentity {
    NSBundle *b = [NSBundle mainBundle];
    NSDictionary *info = b.infoDictionary;
    NSString *bundleID = info[@"CFBundleIdentifier"] ?: @"?";
    NSString *shortVer = info[@"CFBundleShortVersionString"] ?: @"?";
    NSString *build    = info[@"CFBundleVersion"] ?: @"?";
    NSString *exePath  = b.executablePath ?: @"?";
    NSString *bundlePath = b.bundlePath ?: @"?";
    struct stat st;
    char mtime[64] = "?";
    if (stat(exePath.fileSystemRepresentation, &st) == 0) {
        struct tm tm;
        localtime_r(&st.st_mtimespec.tv_sec, &tm);
        strftime(mtime, sizeof(mtime), "%Y-%m-%d %H:%M:%S", &tm);
    }
    printf("[BOOT] bundle=%s id=%s version=%s build=%s exe-mtime=%s\n",
           bundlePath.UTF8String, bundleID.UTF8String,
           shortVer.UTF8String, build.UTF8String, mtime);
}

- (void)installTerminationHandlers {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationWillTerminateNotification:)
                                                     name:UIApplicationWillTerminateNotification
                                                   object:nil];

        signal(SIGTERM, SIG_IGN);
        g_sigterm_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,
                                                  SIGTERM,
                                                  0,
                                                  dispatch_get_main_queue());
        dispatch_source_set_event_handler(g_sigterm_source, ^{
            log_user("[CLEANUP] SIGTERM received; starting best-effort termination cleanup.\n");
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                settings_best_effort_termination_cleanup("SIGTERM");
                _Exit(0);
            });
        });
        dispatch_resume(g_sigterm_source);
    });
}

- (void)applicationWillTerminateNotification:(NSNotification *)note {
    settings_best_effort_termination_cleanup("UIApplicationWillTerminateNotification");
}

- (void)installBarAppearances {
    // Use the system's default glass material for ALL appearance states so the
    // bar never crossfades between transparent and blurred when content
    // scrolls past the edge. This is what UIKit's own apps do post-iOS 15.
    UINavigationBarAppearance *nav = [[UINavigationBarAppearance alloc] init];
    [nav configureWithDefaultBackground];
    UINavigationBar.appearance.standardAppearance = nav;
    UINavigationBar.appearance.scrollEdgeAppearance = nav;
    UINavigationBar.appearance.compactAppearance = nav;
    UINavigationBar.appearance.compactScrollEdgeAppearance = nav;

    UITabBarAppearance *tab = [[UITabBarAppearance alloc] init];
    [tab configureWithDefaultBackground];
    UITabBar.appearance.standardAppearance = tab;
    UITabBar.appearance.scrollEdgeAppearance = tab;
}


#pragma mark - UISceneSession lifecycle


- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options {
    // Called when a new scene session is being created.
    // Use this method to select a configuration to create the new scene with.
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions {
    // Called when the user discards a scene session.
    // If the user discards a scene session while the app is not running, this will be called shortly after application:didFinishLaunchingWithOptions.
    // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    settings_best_effort_termination_cleanup("applicationWillTerminate");
}

@end
