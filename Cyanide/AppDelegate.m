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
#import "TaskRop/RemoteCall.h"
#import <signal.h>
#import <sys/stat.h>
#import <unistd.h>
#include <stdlib.h>
#include <string.h>

// ===========================================================================
//  Delta Force (UE4.22, iOS ARM64) - GWorld hunt, bounded and safe
//
//  Attach strategy is copied verbatim from ProcessDetailViewController
//  (the screen you get after tapping a process):
//
//      // 只做一次短超时尝试（4s）：这个目标历史上附加从未成功，
//      // 失败后立刻走内核直读，不让用户白等三个策略共 40 多秒。
//      session = [[RemoteCallSession alloc] initWithProcess:name
//                                       useMigFilterBypass:NO
//                                  firstExceptionTimeoutMS:4000];
//
//  A long timeout leaves the target hijacked on the exception port and the
//  game dies. 4 s and then fall back to kum_* is the app's own behaviour.
//
//  Budget (all bounded, no big scans):
//      __bss first 8 MB + __common 2.8 MB   page reads   (~1000 pages, proven)
//      then at most 150 candidate probes    (8 bytes each)
//
//  UObject test: a UE object's first qword is its vtable, which lives in the
//  module's __const. So *(cand) inside [base+0x10B1F1C0, base+0x15427A10]
//  means cand really is an object.
// ===========================================================================

#define SEG_A_RVA   0x15D89B40ULL
#define SEG_A_SIZE  0x00800000ULL
#define SEG_B_RVA   0x167B0E40ULL
#define SEG_B_SIZE  0x002B43D0ULL

#define MOD_SIZE    0x16BFE1F0ULL
#define VT_LO_RVA   0x10B1F1C0ULL
#define VT_HI_RVA   0x15427A10ULL

#define MAX_PROBES  150

#define DF_MH_MAGIC_64  0xFEEDFACFu
#define DF_CPU_ARM64    0x0100000Cu
#define DF_MH_EXECUTE   2u

static uint64_t g_base = 0;
static uint64_t g_modHi = 0;

static int dfIsPtr(uint64_t v)
{
    if (v < g_modHi) return 0;
    if (v >= 0x1A0000000ULL) return 0;
    if (v & 7) return 0;
    return 1;
}

static int dfCmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

static uint64_t dfFindBase(uint64_t mapMin, uint64_t mapMax,
                           NSMutableString *out)
{
    const uint64_t STEP = 0x4000, WINDOW = 0x4000000ULL;
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
        return va;
    }
    return 0;
}

NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:16384];
    cyanide_log_sync(@"[DF] ===== gworld hunt =====");

    if (!settings_ensure_kernel_ready()) return @"kernel r/w not ready";

    // ---- 1) find the process in the kernel proc list ----
    static proc_entry_t ents[512];
    int n = proc_list_all(ents, 512);
    if (n <= 0) return @"cannot read proc list";

    uint64_t procAddr = 0;
    int pid = 0;
    char name[PROC_NAME_MAX];
    memset(name, 0, sizeof(name));

    for (int i = 0; i < n; i++) {
        char low[PROC_NAME_MAX];
        int j = 0;
        const char *nm = ents[i].name;
        for (; nm[j] && j < PROC_NAME_MAX - 1; j++) {
            char c = nm[j];
            low[j] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        low[j] = 0;
        if (!procAddr && (strstr(low, "delta") || strstr(low, "dfm"))) {
            procAddr = ents[i].proc;
            pid = (int)ents[i].pid;
            strncpy(name, nm, PROC_NAME_MAX - 1);
        }
    }
    if (!procAddr) return @"DeltaForceClient not running";

    NSString *procName = [NSString stringWithUTF8String:name];
    [out appendFormat:@"target = %s  pid=%d  proc=0x%llx\n", name, pid, procAddr];

    // ---- 2) attach: 4 s, NO bypass, exact proc (same as the app) ----
    g_RC_targetProcOverride = procAddr;
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    RemoteCallSession *session =
        [[RemoteCallSession alloc] initWithProcess:procName
                               useMigFilterBypass:NO
                          firstExceptionTimeoutMS:4000];
    g_RC_targetProcOverride = 0;
    double attachMS = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0;

    if (session) {
        cyanide_log_sync(@"[DF] attach OK %.0fms", attachMS);
        [out appendFormat:@"attach: OK  %.0f ms\n", attachMS];
    } else {
        RemoteCallInitFailure f = remote_call_last_init_failure();
        const char *d = remote_call_init_failure_description(f);
        cyanide_log_sync(@"[DF] attach failed %.0fms reason=%d %s", attachMS, (int)f, d);
        [out appendFormat:@"attach: failed %.0f ms  reason=%d (%s)\n",
                          attachMS, (int)f, d];
    }

    // ---- 3) kernel page-table read (works whether attach succeeded or not) ----
    if (!kum_prepare(procAddr)) {
        [out appendString:@"kum_prepare FAILED\n"];
        if (session) [session destroyRemoteCall];
        return out;
    }

    uint64_t base = dfFindBase(kum_map_min(), kum_map_max(), out);
    if (!base) {
        [out appendString:@"main exec not found\n"];
        if (session) [session destroyRemoteCall];
        return out;
    }
    g_base = base;
    g_modHi = base + MOD_SIZE;
    uint64_t vtLo = base + VT_LO_RVA;
    uint64_t vtHi = base + VT_HI_RVA;
    [out appendFormat:@"vtable range = [0x%llx, 0x%llx]\n", vtLo, vtHi];

    // ---- 4) read __bss + __common (page granular; unmapped pages skipped) ----
    uint64_t total = SEG_A_SIZE + SEG_B_SIZE;
    uint8_t *buf = (uint8_t *)malloc((size_t)total);
    if (!buf) {
        if (session) [session destroyRemoteCall];
        return @"malloc failed";
    }
    memset(buf, 0, (size_t)total);

    CFAbsoluteTime tr = CFAbsoluteTimeGetCurrent();
    const uint64_t PAGE = 0x4000;
    uint64_t off = 0;
    uint64_t ok = 0;
    int failPages = 0;
    while (off < total) {
        uint64_t chunk = total - off;
        if (chunk > PAGE) chunk = PAGE;
        uint64_t rva = (off < SEG_A_SIZE) ? (SEG_A_RVA + off)
                                          : (SEG_B_RVA + (off - SEG_A_SIZE));
        if (kum_read(base + rva, buf + off, (size_t)chunk)) ok += chunk;
        else ++failPages;
        off += chunk;
    }
    double readMS = (CFAbsoluteTimeGetCurrent() - tr) * 1000.0;
    [out appendFormat:@"read %llu/%llu ok=%llu failpages=%d  %.0f ms\n\n",
                      off, total, ok, failPages, readMS];
    cyanide_log_sync(@"[DF] read ok=%llu failpages=%d %.0fms", ok, failPages, readMS);

    // ---- 5) candidate slots: heap pointers referenced >= 2 times ----
    size_t count = (size_t)(off / 8);
    uint64_t *vals = (uint64_t *)malloc(count * 8);
    if (!vals) { free(buf); if (session) [session destroyRemoteCall]; return @"oom"; }
    size_t nv = 0;
    for (size_t i = 0; i < count; i++) {
        uint64_t v;
        memcpy(&v, buf + i * 8, 8);
        if (dfIsPtr(v)) vals[nv++] = v;
    }
    qsort(vals, nv, 8, dfCmp);

    static uint64_t uniq[400000];
    static uint32_t refs[400000];
    size_t nu = 0;
    for (size_t i = 0; i < nv; ) {
        size_t j = i;
        while (j < nv && vals[j] == vals[i]) j++;
        if (nu < 400000) { uniq[nu] = vals[i]; refs[nu] = (uint32_t)(j - i); nu++; }
        i = j;
    }
    free(vals);
    [out appendFormat:@"heap pointers=%zu  unique=%zu\n\n", nv, nu];

    // ---- 6) vtable check on candidates referenced >= 2 times ----
    int probed = 0, objects = 0;
    for (size_t i = 0; i < nu && probed < MAX_PROBES; i++) {
        if (refs[i] < 2) continue;

        uint64_t cand = uniq[i];
        uint64_t first = 0;
        ++probed;
        if (!kum_read(cand, &first, 8)) continue;
        if (first < vtLo || first > vtHi) continue;

        ++objects;
        if (objects <= 40) {
            [out appendFormat:@"  OBJECT 0x%llx  vtable=0x%llx  refs=%u\n",
                              cand, first, refs[i]];
        }
    }

    [out appendFormat:@"\nprobed=%d  objects=%d\n", probed, objects];

    free(buf);
    if (session) [session destroyRemoteCall];
    cyanide_log_sync(@"[DF] ===== done probed=%d objects=%d =====", probed, objects);
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
