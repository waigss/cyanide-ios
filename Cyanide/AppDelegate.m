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
//  Delta Force (UE4.22, iOS ARM64) - SAFE DUMP ONLY
//
//  This build does NOT probe or dereference any unknown pointer. Earlier
//  builds did, and dereferencing bogus addresses walks bogus page-table
//  chains inside the kernel, which panics the device.
//
//  It only copies two known-readable regions to Documents/ and stops:
//
//    A) __bss first 8 MB    RVA 0x15D89B40  size 0x00800000
//       (this exact range completed successfully in an earlier run)
//    B) __common            RVA 0x167B0E40  size 0x002B43D0
//
//  The tail of __bss (0x800000..0xA272F8) is skipped on purpose: that is
//  where the previous build crashed.
//
//  Output:
//    Documents/df_a.bin   (~8 MB)
//    Documents/df_b.bin   (~2.8 MB)
//    Documents/df_info.txt
// ===========================================================================

#define SEG_A_RVA   0x15D89B40ULL
#define SEG_A_SIZE  0x00800000ULL

#define SEG_B_RVA   0x167B0E40ULL
#define SEG_B_SIZE  0x002B43D0ULL

#define DF_MOD_SIZE 0x16BFE1F0ULL

static uint64_t g_dfSlide = 0;

// Read one segment page-by-page and write it out. Returns bytes written.
static uint64_t dfDumpSegment(const char *name, uint64_t rva, uint64_t size,
                              NSMutableString *out)
{
    const uint64_t PAGE = 0x4000;
    uint8_t *buf = (uint8_t *)malloc((size_t)size);
    if (!buf) {
        cyanide_log_sync(@"[DF] %s malloc failed", name);
        [out appendFormat:@"%s: malloc failed\n", name];
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
        if ((off % 0x200000) == 0) {
            cyanide_log_sync(@"[DF] %s read %llu/%llu ok=%llu fail=%d",
                             name, off, size, okBytes, failPages);
        }
    }

    NSString *path = [NSHomeDirectory()
                      stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"Documents/%s.bin", name]];
    NSData *d = [NSData dataWithBytes:buf length:(NSUInteger)size];
    BOOL w = [d writeToFile:path atomically:YES];
    free(buf);

    cyanide_log_sync(@"[DF] %s written=%d ok=%llu/%llu failpages=%d",
                     name, w ? 1 : 0, okBytes, size, failPages);
    [out appendFormat:@"%s: %s  ok=%llu/%llu  unmapped_pages=%d\n",
                      name, w ? @"ok" : @"FAIL", okBytes, size, failPages];
    return okBytes;
}

NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:4096];
    cyanide_log_sync(@"[DF] ===== dump-only begin =====");

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
    if (!targetProc) return @"DeltaForceClient not running";

    cyanide_log_sync(@"[DF] target %s pid=%d", targetName, targetPid);
    [out appendFormat:@"target = %s  pid=%d\n", targetName, targetPid];

    if (!kum_prepare(targetProc)) {
        return @"kum_prepare failed";
    }

    uint64_t base = 0;
    if (!kum_main_executable_base(&base) || base < 0x100000000ULL) {
        return @"cannot locate main executable";
    }
    g_dfSlide = base;

    cyanide_log_sync(@"[DF] base = 0x%llx", base);
    [out appendFormat:@"base   = 0x%llx\n", base];
    [out appendFormat:@"A      = 0x%llx  %llu bytes\n",
                      base + SEG_A_RVA, SEG_A_SIZE];
    [out appendFormat:@"B      = 0x%llx  %llu bytes\n\n",
                      base + SEG_B_RVA, SEG_B_SIZE];

    // Segment A: proven-safe first 8 MB of __bss.
    uint64_t a = dfDumpSegment("df_a", SEG_A_RVA, SEG_A_SIZE, out);

    // Segment B: __common. Kept separate so that if it ever fails we still
    // have df_a.bin on disk.
    uint64_t b = dfDumpSegment("df_b", SEG_B_RVA, SEG_B_SIZE, out);

    // Info file
    NSString *info = [NSString stringWithFormat:
        @"base=0x%llx\nA_rva=0x%llx\nA_size=%llu\nA_ok=%llu\n"
        @"B_rva=0x%llx\nB_size=%llu\nB_ok=%llu\n",
        base, SEG_A_RVA, SEG_A_SIZE, a,
        SEG_B_RVA, SEG_B_SIZE, b];
    [[info dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:[NSHomeDirectory()
                     stringByAppendingPathComponent:@"Documents/df_info.txt"]
         atomically:YES];

    cyanide_log_sync(@"[DF] ===== dump-only done =====");
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
