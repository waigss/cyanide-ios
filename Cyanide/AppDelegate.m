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
//  Delta Force (UE4.22, iOS ARM64) - HEAP SIGNATURE SCAN
//
//  Uses kum_read (kernel page-table translation): no attach, no remote thread.
//
//  SAFETY RULES:
//    * Every address read is FIXED and page-aligned. Nothing is derived from a
//      value found in memory.
//    * The signature test only inspects values inside the page already read.
//      It never dereferences them.
//
//  Signature (ULevel::Actors):
//      [A + 0x28]  heap pointer   (Data)
//      [A + 0x30]  int32 count    (ArrayNum)  200..200000
//      [A + 0x34]  int32 max      (ArrayMax)  >= count
//
//  A live level during a match has hundreds..thousands of actors, so
//  requiring count >= 200 removes almost every false positive.
//
//  Heap band comes from offline analysis of the __bss dump: every real object
//  pointer landed in 0x140000000..0x160000000.
// ===========================================================================

#define MOD_SIZE        0x16BFE1F0ULL
#define HEAP_LO         0x140000000ULL
#define HEAP_HI         0x160000000ULL
#define SCAN_PAGE       0x4000ULL
#define MIN_ACTORS      200
#define MAX_ACTORS      200000
#define MAX_CANDIDATES  4000

#define DF_MH_MAGIC_64  0xFEEDFACFu
#define DF_CPU_ARM64    0x0100000Cu
#define DF_MH_EXECUTE   2u

static uint64_t g_dfBase = 0;
static uint64_t g_dfModHi = 0;

static int dfPlausible(uint64_t v)
{
    if (v < g_dfModHi) return 0;
    if (v >= HEAP_HI + 0x40000000ULL) return 0;
    if (v & 7) return 0;
    return 1;
}

static uint64_t dfFindMainExec(uint64_t mapMin, uint64_t mapMax,
                               NSMutableString *out)
{
    const uint64_t STEP = 0x4000;
    const uint64_t WINDOW = 0x4000000ULL;
    uint64_t start = mapMin & ~(STEP - 1);
    uint64_t limit = start + WINDOW;
    if (limit > mapMax) limit = mapMax;

    uint32_t mh[8];
    for (uint64_t va = start; va < limit; va += STEP) {
        if (!kum_read(va, mh, sizeof(mh))) continue;
        if (mh[0] != DF_MH_MAGIC_64) continue;
        if (mh[1] != DF_CPU_ARM64) continue;
        if (mh[3] != DF_MH_EXECUTE) continue;
        [out appendFormat:@"base 0x%llx ncmds=%u\n", va, mh[4]];
        cyanide_log_sync(@"[DF] base 0x%llx ncmds=%u", va, mh[4]);
        return va;
    }
    return 0;
}

NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:16384];
    cyanide_log_sync(@"[DF] ===== heap signature scan =====");

    if (!settings_ensure_kernel_ready()) return @"kernel r/w not ready";

    static proc_entry_t ents[512];
    int n = proc_list_all(ents, 512);
    if (n <= 0) return @"cannot read proc list";

    uint64_t targetProc = 0;
    int targetPid = 0;
    char targetName[PROC_NAME_MAX];
    memset(targetName, 0, sizeof(targetName));

    for (int i = 0; i < n; i++) {
        char low[PROC_NAME_MAX];
        int j = 0;
        const char *nm = ents[i].name;
        for (; nm[j] && j < PROC_NAME_MAX - 1; j++) {
            char c = nm[j];
            low[j] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        low[j] = 0;
        if (!targetProc && (strstr(low, "delta") || strstr(low, "dfm"))) {
            targetProc = ents[i].proc;
            targetPid  = (int)ents[i].pid;
            strncpy(targetName, nm, PROC_NAME_MAX - 1);
        }
    }
    if (!targetProc) return @"DeltaForceClient not running";
    [out appendFormat:@"target = %s pid=%d\n", targetName, targetPid];

    if (!kum_prepare(targetProc)) return @"kum_prepare FAILED";

    uint64_t base = dfFindMainExec(kum_map_min(), kum_map_max(), out);
    if (!base) {
        [out appendString:@"main exec not found\n"];
        return out;
    }
    g_dfBase = base;
    g_dfModHi = base + MOD_SIZE;

    [out appendFormat:@"heap band = [0x%llx, 0x%llx)\n\n", HEAP_LO, HEAP_HI];

    static uint8_t page[SCAN_PAGE];
    static uint64_t cand[MAX_CANDIDATES];
    int ncand = 0;

    uint64_t pages = (HEAP_HI - HEAP_LO) / SCAN_PAGE;
    uint64_t readable = 0;

    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();

    for (uint64_t i = 0; i < pages; i++) {
        uint64_t va = HEAP_LO + i * SCAN_PAGE;

        if ((i % 2048) == 0) {
            cyanide_log_sync(@"[DF] page %llu/%llu readable=%llu cand=%d",
                             i, pages, readable, ncand);
        }

        if (!kum_read(va, page, SCAN_PAGE)) continue;
        ++readable;

        const uint64_t last = SCAN_PAGE - 0x40;
        for (uint64_t off = 0; off <= last; off += 8) {
            uint64_t data;
            int32_t num, mx;
            memcpy(&data, page + off + 0x28, 8);
            memcpy(&num,  page + off + 0x30, 4);
            memcpy(&mx,   page + off + 0x34, 4);

            if (num < MIN_ACTORS || num > MAX_ACTORS) continue;
            if (mx < num || mx > num * 2 + 1024) continue;
            if (!dfPlausible(data)) continue;

            if (ncand < MAX_CANDIDATES) cand[ncand++] = va + off;
        }
    }

    double ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0;
    cyanide_log_sync(@"[DF] scan done pages=%llu readable=%llu cand=%d %.0fms",
                     pages, readable, ncand, ms);
    [out appendFormat:@"pages=%llu readable=%llu candidates=%d  %.0f ms\n\n",
                      pages, readable, ncand, ms];

    int shown = 0;
    for (int i = 0; i < ncand && shown < 40; i++) {
        uint64_t a = cand[i];
        uint64_t data = 0;
        int32_t num = 0, mx = 0;
        if (!kum_read(a + 0x28, &data, 8)) continue;
        if (!kum_read(a + 0x30, &num, 4)) continue;
        if (!kum_read(a + 0x34, &mx, 4)) continue;
        [out appendFormat:@"  ULevel? 0x%llx  actors=0x%llx  n=%d max=%d\n",
                          a, data, num, mx];
        shown++;
    }
    if (ncand == 0) [out appendString:@"  (none)\n"];

    return out;
}

void df_scan_run(void)
{
    NSString *r = df_scan_collect();
    if (!r) return;
    [[r dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[NSHomeDirectory()
                     stringByAppendingPathComponent:@"Documents/df_result.txt"]
         atomically:YES];
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
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions {
}

- (void)applicationWillTerminate:(UIApplication *)application {
    settings_best_effort_termination_cleanup("applicationWillTerminate");
}

@end
