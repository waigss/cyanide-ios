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
#import <signal.h>
#import <sys/stat.h>
#import <unistd.h>
#include <stdlib.h>
#include <string.h>

// ===========================================================================
//  Delta Force (UE4.22, iOS ARM64) memory scan
//
//  RVAs obtained from static analysis of the Mach-O binary.
//  All addresses are relative to the __TEXT start, which equals the value
//  returned by _dyld_get_image_header(0) (vmaddr 0x100000000).
//
//    __bss       RVA 0x15D89B40   size 0x0A272F8
//    __common    RVA 0x167B0E40   size 0x02B43D0
//
//  Goal: recover the GWorld -> UWorld -> Levels -> ULevel -> Actors chain.
//
//    UWorld::Levels candidate offsets: +0x28 or +0x158
//        TArray<ULevel*> { Data @ +0x00, Num @ +0x08, Max @ +0x0C }
//    ULevel::Actors  offset +0x28
//        TArray<AActor*> { Data @ +0x00, Num @ +0x08, Max @ +0x0C }
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
static int dfLooksLikeWorldTArray(uint64_t addr, uint64_t off,
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

void df_scan_run(void)
{
    printf("\n[DF] ===== Delta Force scan begin =====\n");

    if (!settings_ensure_kernel_ready()) {
        printf("[DF] kernel r/w not ready\n");
        return;
    }
    printf("[DF] kernel ready\n");

    if (init_remote_call("DeltaForceClient", false) != 0) {
        static const char *names[] = {
            "DeltaForce", "DeltaForceClient-DeltaForceClient",
            "deltaforce", "DeltaForceMobile", "DeltaForceClientIos"
        };
        int attached = 0;
        for (int i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
            printf("[DF] try attach %s ...\n", names[i]);
            if (init_remote_call(names[i], false) == 0) { attached = 1; break; }
        }
        if (!attached) {
            printf("[DF] attach failed for all names\n");
            return;
        }
    }
    printf("[DF] attached\n");

    uint64_t hdr = do_remote_call_stable(10, "_dyld_get_image_header",
                                         0, 0, 0, 0, 0, 0, 0, 0);
    printf("[DF] _dyld_get_image_header(0) = 0x%llx\n", hdr);
    if (hdr < 0x100000000ULL) {
        printf("[DF] invalid image header\n");
        destroy_remote_call();
        return;
    }
    g_dfSlide = hdr;
    printf("[DF] base   = 0x%llx\n", g_dfSlide);
    printf("[DF] bss    = 0x%llx\n", dfVa(DF_BSS_RVA));
    printf("[DF] common = 0x%llx\n", dfVa(DF_COM_RVA));

    // ---- read __bss + __common ----
    uint64_t total = DF_BSS_SIZE + DF_COM_SIZE;
    uint8_t *buf = (uint8_t *)malloc((size_t)total);
    if (!buf) {
        printf("[DF] malloc %llu failed\n", total);
        destroy_remote_call();
        return;
    }
    memset(buf, 0, (size_t)total);

    const uint64_t CHUNK = 0x40000;
    uint64_t off = 0;
    int fails = 0;
    uint64_t nextLog = 0x200000;
    while (off < total) {
        uint64_t n = total - off;
        if (n > CHUNK) n = CHUNK;
        uint64_t rva = (off < DF_BSS_SIZE)
                     ? (DF_BSS_RVA + off)
                     : (DF_COM_RVA + (off - DF_BSS_SIZE));
        if (!remote_read(dfVa(rva), buf + off, n)) {
            if (++fails > 16) break;
        }
        off += n;
        if (off >= nextLog) {
            printf("[DF] read %llu / %llu\n", off, total);
            nextLog += 0x200000;
        }
    }
    printf("[DF] read done %llu/%llu fails=%d\n", off, total, fails);

    // ---- collect plausible object pointers ----
    const size_t MAXC = 200000;
    uint64_t *cands = (uint64_t *)malloc(sizeof(uint64_t) * MAXC);
    if (!cands) {
        printf("[DF] cand alloc failed\n");
        free(buf);
        destroy_remote_call();
        return;
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
    printf("[DF] raw candidates = %zu\n", nc);

    qsort(cands, nc, sizeof(uint64_t), dfCmpU64);
    size_t nu = 0;
    for (size_t i = 0; i < nc; i++) {
        if (i == 0 || cands[i] != cands[i - 1]) cands[nu++] = cands[i];
    }
    printf("[DF] unique candidates = %zu\n", nu);

    // ---- probe candidates ----
    static char report[1 << 17];
    size_t rl = 0;
    memset(report, 0, sizeof(report));
    rl += snprintf(report + rl, sizeof(report) - rl,
                   "base=0x%llx\n", hdr);
    rl += snprintf(report + rl, sizeof(report) - rl,
                   "bss=0x%llx common=0x%llx\n",
                   dfVa(DF_BSS_RVA), dfVa(DF_COM_RVA));

    int hits28 = 0, hits158 = 0;
    uint64_t bestWorld = 0, bestLevels = 0, bestOff = 0;
    uint32_t bestNum = 0;

    size_t probeLimit = nu < 6000 ? nu : 6000;
    for (size_t i = 0; i < probeLimit; i++) {
        uint64_t c = cands[i];
        uint64_t data; uint32_t num;

        if (dfLooksLikeWorldTArray(c, 0x28, &data, &num)) {
            hits28++;
            uint64_t lv = dfRd64(data);
            uint64_t act = 0; uint32_t an = 0;
            int lvlOk = dfLooksLikeLevel(lv, &act, &an);
            printf("[DF] HIT 0x28 world=0x%llx levels=0x%llx n=%u level0=0x%llx %s\n",
                   c, data, num, lv, lvlOk ? "LEVEL_OK" : "");
            if (rl < sizeof(report) - 256) {
                rl += snprintf(report + rl, sizeof(report) - rl,
                               "WORLD28 world=0x%llx levels=0x%llx n=%u level0=0x%llx act=0x%llx an=%u\n",
                               c, data, num, lv, lvlOk ? act : 0ULL, lvlOk ? an : 0);
            }
            if (lvlOk && !bestWorld) {
                bestWorld = c; bestLevels = data; bestNum = num; bestOff = 0x28;
            }
        }
        if (dfLooksLikeWorldTArray(c, 0x158, &data, &num)) {
            hits158++;
            uint64_t lv = dfRd64(data);
            uint64_t act = 0; uint32_t an = 0;
            int lvlOk = dfLooksLikeLevel(lv, &act, &an);
            printf("[DF] HIT 0x158 world=0x%llx levels=0x%llx n=%u level0=0x%llx %s\n",
                   c, data, num, lv, lvlOk ? "LEVEL_OK" : "");
            if (rl < sizeof(report) - 256) {
                rl += snprintf(report + rl, sizeof(report) - rl,
                               "WORLD158 world=0x%llx levels=0x%llx n=%u level0=0x%llx act=0x%llx an=%u\n",
                               c, data, num, lv, lvlOk ? act : 0ULL, lvlOk ? an : 0);
            }
            if (lvlOk && !bestWorld) {
                bestWorld = c; bestLevels = data; bestNum = num; bestOff = 0x158;
            }
        }
    }

    printf("[DF] world hits: +0x28=%d +0x158=%d\n", hits28, hits158);
    printf("[DF] best world=0x%llx levels_off=0x%llx\n", bestWorld, bestOff);

    // ---- locate the global slot that holds this UWorld (= GWorld) ----
    if (bestWorld) {
        for (uint64_t o = 0; o + 8 <= off; o += 8) {
            uint64_t v;
            memcpy(&v, buf + o, 8);
            if (v != bestWorld) continue;
            uint64_t slotRva = (o < DF_BSS_SIZE)
                             ? (DF_BSS_RVA + o)
                             : (DF_COM_RVA + (o - DF_BSS_SIZE));
            printf("[DF] >>> GWORLD SLOT base+0x%llx = 0x%llx\n", slotRva, v);
            if (rl < sizeof(report) - 256) {
                rl += snprintf(report + rl, sizeof(report) - rl,
                               "GWORLD_SLOT rva=0x%llx world=0x%llx\n",
                               slotRva, v);
            }
        }

        uint64_t lv = dfRd64(bestLevels);
        uint64_t act = 0; uint32_t an = 0;
        if (dfLooksLikeLevel(lv, &act, &an)) {
            printf("[DF] LEVEL0=0x%llx actors=0x%llx n=%u\n", lv, act, an);
            if (rl < sizeof(report) - 256) {
                rl += snprintf(report + rl, sizeof(report) - rl,
                               "LEVEL0 level=0x%llx actors=0x%llx n=%u\n",
                               lv, act, an);
            }
            for (uint32_t k = 0; k < an && k < 8; k++) {
                uint64_t a = dfRd64(act + (uint64_t)k * 8);
                printf("[DF]   actor[%u]=0x%llx\n", k, a);
                if (rl < sizeof(report) - 128) {
                    rl += snprintf(report + rl, sizeof(report) - rl,
                                   "ACTOR %u = 0x%llx\n", k, a);
                }
            }

            uint8_t lvbuf[0x200];
            if (remote_read(lv, lvbuf, sizeof(lvbuf))) {
                for (int row = 0; row < 0x200; row += 32) {
                    if (rl > sizeof(report) - 256) break;
                    rl += snprintf(report + rl, sizeof(report) - rl,
                                   "LV%03X ", row);
                    for (int j = 0; j < 32; j++) {
                        rl += snprintf(report + rl, sizeof(report) - rl,
                                       "%02X", lvbuf[row + j]);
                    }
                    rl += snprintf(report + rl, sizeof(report) - rl, "\n");
                }
            }
        }
    }

    // ---- write report ----
    NSString *path = [NSHomeDirectory()
                      stringByAppendingPathComponent:@"Documents/df_result.txt"];
    NSString *txt = [[NSString alloc] initWithBytes:report
                                             length:rl
                                           encoding:NSUTF8StringEncoding];
    NSError *err = nil;
    BOOL ok = [txt writeToFile:path
                    atomically:YES
                      encoding:NSUTF8StringEncoding
                         error:&err];
    printf("[DF] report -> %s (%s)\n", path.UTF8String, ok ? "ok" : "FAIL");
    if (err) printf("[DF] write error: %s\n", err.localizedDescription.UTF8String);

    free(cands);
    free(buf);
    destroy_remote_call();
    printf("[DF] ===== scan done =====\n");
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

    // Delay the Delta Force scan a few seconds so kernel r/w can come up.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        df_scan_run();
    });

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
