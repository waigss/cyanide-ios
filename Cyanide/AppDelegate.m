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
#import "TaskRop/RemoteCall.h"
#import "inspector/CyanideLog.h"
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
//  RVAs come from static analysis of the Mach-O binary. All addresses are
//  relative to the __TEXT start, which equals the value returned by
//  _dyld_get_image_header(0) (vmaddr 0x100000000).
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

#define DF_BSS_RVA   0x15D89B40ULL
#define DF_BSS_SIZE  0x0A272F8ULL
#define DF_COM_RVA   0x167B0E40ULL
#define DF_COM_SIZE  0x02B43D0ULL
#define DF_MOD_SIZE  0x16BFE1F0ULL

static uint64_t g_dfSlide = 0;

static inline uint64_t dfVa(uint64_t rva) { return g_dfSlide + rva; }

static uint64_t dfRd64(uint64_t a)
{
    uint64_t v = 0;
    if (!remote_read(a, &v, 8)) return 0;
    return v;
}

static uint32_t dfRd32(uint64_t a)
{
    uint32_t v = 0;
    if (!remote_read(a, &v, 4)) return 0;
    return v;
}

static int dfPlausiblePtr(uint64_t p)
{
    if (p < 0x100000000ULL)   return 0;
    if (p >= 0x8000000000ULL) return 0;
    if (p & 7)                return 0;
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

// Returns 1 when [addr + off] looks like a TArray whose elements are pointers.
static int dfLooksLikeTArray(uint64_t addr, uint64_t off,
                             uint64_t *outData, uint32_t *outNum)
{
    uint64_t data = dfRd64(addr + off);
    uint32_t num  = dfRd32(addr + off + 8);
    uint32_t max  = dfRd32(addr + off + 0xC);

    if (!dfPlausiblePtr(data)) return 0;
    if (num < 1 || num > 200000) return 0;
    if (max < num || max > num * 2 + 1024) return 0;

    uint64_t e0 = dfRd64(data);
    if (!dfPlausiblePtr(e0)) return 0;

    *outData = data;
    *outNum  = num;
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

// Blocking. Returns the report text, or nil on hard failure.
NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:16384];
    cyanide_log(@"[DF] ===== scan begin =====");

    if (!settings_ensure_kernel_ready()) {
        cyanide_log(@"[DF] kernel r/w not ready");
        return @"kernel r/w not ready";
    }
    cyanide_log(@"[DF] kernel ready");

    // ---- enumerate the kernel proc list and pick the game ----
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
            (strstr(low, "delta") || strstr(low, "dfm") ||
             strstr(low, "tmgp") || strstr(low, "game"))) {
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
    [out appendFormat:@"\ntarget = %s  pid=%d  proc=0x%llx\n\n",
                      targetName, targetPid, targetProc];

    // ---- attach by exact kernel proc address (bypasses name lookup) ----
    g_RC_targetProcOverride = targetProc;
    int rc = init_remote_call_with_first_exception_timeout(targetName, false, 45000);
    g_RC_targetProcOverride = 0;

    if (rc != 0) {
        RemoteCallInitFailure f = remote_call_last_init_failure();
        const char *desc = remote_call_init_failure_description(f);
        cyanide_log(@"[DF] attach failed rc=%d failure=%d %s", rc, (int)f, desc);
        [out appendFormat:@"attach FAILED  rc=%d  failure=%d  (%s)\n",
                          rc, (int)f, desc];
        return out;
    }
    cyanide_log(@"[DF] attached");
    [out appendString:@"attached OK\n"];

    uint64_t hdr = do_remote_call_stable(10, "_dyld_get_image_header",
                                         0, 0, 0, 0, 0, 0, 0, 0);
    cyanide_log(@"[DF] _dyld_get_image_header(0) = 0x%llx", hdr);
    if (hdr < 0x100000000ULL) {
        cyanide_log(@"[DF] invalid image header");
        destroy_remote_call();
        return @"invalid _dyld_get_image_header";
    }
    g_dfSlide = hdr;

    [out appendFormat:@"base   = 0x%llx\n", hdr];
    [out appendFormat:@"bss    = 0x%llx\n", dfVa(DF_BSS_RVA)];
    [out appendFormat:@"common = 0x%llx\n\n", dfVa(DF_COM_RVA)];

    // ---- read __bss + __common ----
    uint64_t total = DF_BSS_SIZE + DF_COM_SIZE;
    uint8_t *buf = (uint8_t *)malloc((size_t)total);
    if (!buf) {
        cyanide_log(@"[DF] malloc failed");
        destroy_remote_call();
        return @"malloc failed";
    }
    memset(buf, 0, (size_t)total);

    const uint64_t CHUNK = 0x40000;
    uint64_t off = 0;
    int fails = 0;
    uint64_t nextLog = 0x400000;
    while (off < total) {
        uint64_t chunk = total - off;
        if (chunk > CHUNK) chunk = CHUNK;
        uint64_t rva = (off < DF_BSS_SIZE)
                     ? (DF_BSS_RVA + off)
                     : (DF_COM_RVA + (off - DF_BSS_SIZE));
        if (!remote_read(dfVa(rva), buf + off, chunk)) {
            if (++fails > 32) break;
        }
        off += chunk;
        if (off >= nextLog) {
            cyanide_log(@"[DF] read %llu / %llu", off, total);
            nextLog += 0x400000;
        }
    }
    cyanide_log(@"[DF] read done %llu/%llu fails=%d", off, total, fails);
    [out appendFormat:@"read %llu/%llu bytes (fails=%d)\n", off, total, fails];

    // ---- collect plausible object pointers ----
    const size_t MAXC = 300000;
    uint64_t *cands = (uint64_t *)malloc(sizeof(uint64_t) * MAXC);
    if (!cands) {
        free(buf);
        destroy_remote_call();
        return @"cand alloc failed";
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
    size_t nu = 0;
    for (size_t i = 0; i < nc; i++) {
        if (i == 0 || cands[i] != cands[i - 1]) cands[nu++] = cands[i];
    }
    cyanide_log(@"[DF] unique candidates = %zu", nu);
    [out appendFormat:@"unique candidates = %zu\n\n", nu];

    // ---- probe ----
    int hits28 = 0, hits158 = 0;
    uint64_t bestWorld = 0, bestLevels = 0, bestOff = 0;

    size_t probeLimit = nu < 8000 ? nu : 8000;
    for (size_t i = 0; i < probeLimit; i++) {
        uint64_t c = cands[i];
        uint64_t data; uint32_t num;

        if (dfLooksLikeTArray(c, 0x28, &data, &num)) {
            hits28++;
            uint64_t lv = dfRd64(data);
            uint64_t act = 0; uint32_t an = 0;
            int lvlOk = dfLooksLikeLevel(lv, &act, &an);
            cyanide_log(@"[DF] HIT 0x28 world=0x%llx levels=0x%llx n=%u level0=0x%llx %s",
                        c, data, num, lv, lvlOk ? "LEVEL_OK" : "");
            [out appendFormat:@"WORLD@0x28 world=0x%llx levels=0x%llx n=%u level0=0x%llx "
                              @"actors=0x%llx an=%u %s\n",
                              c, data, num, lv, lvlOk ? act : 0ULL,
                              lvlOk ? an : 0, lvlOk ? "LEVEL_OK" : ""];
            if (lvlOk && !bestWorld) {
                bestWorld = c; bestLevels = data; bestOff = 0x28;
            }
        }
        if (dfLooksLikeTArray(c, 0x158, &data, &num)) {
            hits158++;
            uint64_t lv = dfRd64(data);
            uint64_t act = 0; uint32_t an = 0;
            int lvlOk = dfLooksLikeLevel(lv, &act, &an);
            cyanide_log(@"[DF] HIT 0x158 world=0x%llx levels=0x%llx n=%u level0=0x%llx %s",
                        c, data, num, lv, lvlOk ? "LEVEL_OK" : "");
            [out appendFormat:@"WORLD@0x158 world=0x%llx levels=0x%llx n=%u level0=0x%llx "
                              @"actors=0x%llx an=%u %s\n",
                              c, data, num, lv, lvlOk ? act : 0ULL,
                              lvlOk ? an : 0, lvlOk ? "LEVEL_OK" : ""];
            if (lvlOk && !bestWorld) {
                bestWorld = c; bestLevels = data; bestOff = 0x158;
            }
        }
    }

    cyanide_log(@"[DF] world hits: 0x28=%d 0x158=%d", hits28, hits158);
    [out appendFormat:@"\nworld hits: +0x28=%d  +0x158=%d\n", hits28, hits158];

    // ---- find the global slot holding this UWorld (= GWorld) ----
    if (bestWorld) {
        [out appendFormat:@"best world = 0x%llx (levels at +0x%llx)\n",
                          bestWorld, bestOff];
        for (uint64_t o = 0; o + 8 <= off; o += 8) {
            uint64_t v;
            memcpy(&v, buf + o, 8);
            if (v != bestWorld) continue;
            uint64_t slotRva = (o < DF_BSS_SIZE)
                             ? (DF_BSS_RVA + o)
                             : (DF_COM_RVA + (o - DF_BSS_SIZE));
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
            if (remote_read(lv, lvbuf, sizeof(lvbuf))) {
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
    destroy_remote_call();
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
