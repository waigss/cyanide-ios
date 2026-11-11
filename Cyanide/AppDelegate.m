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
//  Delta Force (UE4.22, iOS ARM64) - SAFE RAW DUMP
//
//  Rules followed by this build:
//    * Uses KernelUserMemory (kum_read): kernel page-table translation.
//      NO process attach, NO remote thread, NO exception port.
//    * NEVER dereferences a value read out of memory. Every address touched
//      is computed from the module base plus a fixed RVA, or is a fixed
//      page-aligned probe inside [map_min, map_min + 64 MB].
//
//  Why the previous builds died: they treated values found in __bss as
//  pointers and read through them. Bogus values walk bogus page-table chains
//  and the kernel panics. This build does none of that.
//
//  Output (Documents/):
//    df_a.bin    __bss      first 8 MB   (RVA 0x15D89B40)
//    df_b.bin    __common   2.8 MB       (RVA 0x167B0E40)
//    df_info.txt
// ===========================================================================

#define SEG_A_RVA   0x15D89B40ULL
#define SEG_A_SIZE  0x00800000ULL

#define SEG_B_RVA   0x167B0E40ULL
#define SEG_B_SIZE  0x002B43D0ULL

#define MH_MAGIC_64   0xFEEDFACFu
#define CPU_TYPE_ARM64 0x0100000Cu
#define MH_EXECUTE     2u

static uint64_t g_dfSlide = 0;

// Locate the main executable by scanning page-aligned addresses upward from
// map_min and looking for a Mach-O header with filetype == MH_EXECUTE.
// Dylibs/frameworks are MH_DYLIB (6), so they are skipped automatically.
// Every read here is at a fixed computed address; nothing is dereferenced.
static uint64_t dfFindMainExec(uint64_t mapMin, uint64_t mapMax,
                               NSMutableString *out)
{
    const uint64_t STEP   = 0x4000;
    const uint64_t WINDOW = 0x4000000ULL;   // scan at most 64 MB upward

    uint64_t start = mapMin & ~(STEP - 1);
    uint64_t limit = start + WINDOW;
    if (limit > mapMax) limit = mapMax;

    uint32_t mh[8];
    uint64_t tried = 0;

    for (uint64_t va = start; va < limit; va += STEP) {
        ++tried;
        if (!kum_read(va, mh, sizeof(mh))) continue;
        if (mh[0] != MH_MAGIC_64) continue;
        if (mh[1] != CPU_TYPE_ARM64) continue;
        if (mh[3] != MH_EXECUTE) {
            // a dylib / bundle header: remember it in the log, keep going
            [out appendFormat:@"  skip 0x%llx filetype=%u (not MH_EXECUTE)\n",
                              va, mh[3]];
            continue;
        }
        [out appendFormat:@"  FOUND 0x%llx magic=0x%08x cputype=0x%08x "
                          @"filetype=%u ncmds=%u\n",
                          va, mh[0], mh[1], mh[3], mh[4]];
        cyanide_log_sync(@"[DF] main exec 0x%llx ncmds=%u", va, mh[4]);
        return va;
    }

    [out appendFormat:@"  scanned %llu pages, no MH_EXECUTE header\n", tried);
    return 0;
}

static uint64_t dfDumpSegment(NSString *name, uint64_t rva, uint64_t size,
                              NSMutableString *out)
{
    const uint64_t PAGE = 0x4000;
    uint8_t *buf = (uint8_t *)malloc((size_t)size);
    if (!buf) {
        [out appendFormat:@"%@: malloc failed\n", name];
        return 0;
    }
    memset(buf, 0, (size_t)size);

    uint64_t off = 0;
    int failPages = 0;
    uint64_t okBytes = 0;

    while (off < size) {
        uint64_t chunk = size - off;
        if (chunk > PAGE) chunk = PAGE;
        if (kum_read(g_dfSlide + rva + off, buf + off, (size_t)chunk)) {
            okBytes += chunk;
        } else {
            ++failPages;
        }
        off += chunk;
    }

    NSString *path = [NSHomeDirectory()
                      stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"Documents/%@.bin", name]];
    NSData *d = [NSData dataWithBytes:buf length:(NSUInteger)size];
    BOOL w = [d writeToFile:path atomically:YES];
    free(buf);

    cyanide_log_sync(@"[DF] %@ written=%d ok=%llu/%llu failpages=%d",
                     name, w ? 1 : 0, okBytes, size, failPages);
    [out appendFormat:@"%@: %@  ok=%llu/%llu  unmapped_pages=%d / %llu\n",
                      name, w ? @"ok" : @"FAIL",
                      okBytes, size, failPages, size / PAGE];
    return okBytes;
}

NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:8192];
    cyanide_log_sync(@"[DF] ===== safe dump begin =====");

    if (!settings_ensure_kernel_ready()) {
        return @"kernel r/w not ready";
    }

    static proc_entry_t ents[512];
    int n = proc_list_all(ents, 512);
    [out appendFormat:@"proc_count = %d\n", n];
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
    if (!targetProc) {
        [out appendString:@"DeltaForceClient not running\n"];
        return out;
    }

    cyanide_log_sync(@"[DF] target %s pid=%d", targetName, targetPid);
    [out appendFormat:@"target = %s  pid=%d\n", targetName, targetPid];

    if (!kum_prepare(targetProc)) {
        [out appendString:@"kum_prepare FAILED\n"];
        return out;
    }

    uint64_t mapMin = kum_map_min();
    uint64_t mapMax = kum_map_max();
    [out appendFormat:@"map    = [0x%llx, 0x%llx]\n\n", mapMin, mapMax];

    // ---- locate the main executable (fixed-address probes only) ----
    uint64_t base = dfFindMainExec(mapMin, mapMax, out);
    if (!base) {
        [out appendString:@"\nmain executable not found -> nothing read\n"];
        return out;
    }

    g_dfSlide = base;
    [out appendFormat:@"\nchosen base = 0x%llx\n", base];
    [out appendFormat:@"A = 0x%llx  %llu bytes\n", base + SEG_A_RVA, SEG_A_SIZE];
    [out appendFormat:@"B = 0x%llx  %llu bytes\n\n", base + SEG_B_RVA, SEG_B_SIZE];

    uint64_t a = dfDumpSegment(@"df_a", SEG_A_RVA, SEG_A_SIZE, out);
    uint64_t b = dfDumpSegment(@"df_b", SEG_B_RVA, SEG_B_SIZE, out);

    NSString *info = [NSString stringWithFormat:
        @"base=0x%llx\nmap_min=0x%llx\nmap_max=0x%llx\n"
        @"A_rva=0x%llx\nA_size=%llu\nA_ok=%llu\n"
        @"B_rva=0x%llx\nB_size=%llu\nB_ok=%llu\n",
        base, mapMin, mapMax,
        SEG_A_RVA, SEG_A_SIZE, a,
        SEG_B_RVA, SEG_B_SIZE, b];
    [[info dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[NSHomeDirectory()
                     stringByAppendingPathComponent:@"Documents/df_info.txt"]
         atomically:YES];

    cyanide_log_sync(@"[DF] ===== done =====");
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
