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
#import "kexploit/kutils.h"
#import "TaskRop/RemoteCall.h"
#import <signal.h>
#import <sys/stat.h>
#import <unistd.h>
#include <stdlib.h>
#include <string.h>

// ===========================================================================
//  Delta Force - RemoteCall attach probe
//
//  Cyanide has no dylib injection (by design: "No SpringBoard dylibs, no
//  Substrate hooks"). Its supported cross-process bridge is RemoteCall.
//
//  Earlier attempts passed useMigFilterBypass = false, which made
//  init_remote_call time out after ~2 minutes: iOS 17+ filters exception-port
//  registration through a MIG filter, so the bypass thread is required.
//
//  This build only proves the channel:
//    1. find DeltaForceClient in the kernel proc list
//    2. attach with g_RC_targetProcOverride (exact proc, no name lookup)
//       and useMigFilterBypass = true
//    3. read the module header and a few slots to prove remote_read works
//
//  No heap scanning, no page-table walking.
// ===========================================================================

static uint64_t g_dfBase = 0;

NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:8192];
    cyanide_log_sync(@"[DF] ===== remote-call probe =====");

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
    [out appendFormat:@"target = %s  pid=%d  proc=0x%llx\n\n",
                      targetName, targetPid, targetProc];

    // ---- attach with MIG-filter bypass + exact proc address ----
    cyanide_log_sync(@"[DF] attach with bypass=true ...");
    g_RC_targetProcOverride = targetProc;
    int rc = init_remote_call_with_first_exception_timeout(targetName, true, 60000);
    g_RC_targetProcOverride = 0;

    [out appendFormat:@"init_remote_call(bypass=YES) rc=%d\n", rc];

    if (rc != 0) {
        RemoteCallInitFailure f = remote_call_last_init_failure();
        const char *desc = remote_call_init_failure_description(f);
        uint32_t fp = remote_call_last_init_failure_pid();
        cyanide_log_sync(@"[DF] attach FAILED rc=%d failure=%d pid=%u %s",
                         rc, (int)f, fp, desc);
        [out appendFormat:@"  failure=%d  pid=%u\n  reason=%s\n",
                          (int)f, fp, desc];
        return out;
    }

    cyanide_log_sync(@"[DF] attached");
    [out appendString:@"ATTACHED\n\n"];

    // ---- prove reads ----
    uint64_t hdr = do_remote_call_stable(10, "_dyld_get_image_header",
                                         0, 0, 0, 0, 0, 0, 0, 0);
    [out appendFormat:@"_dyld_get_image_header(0) = 0x%llx\n", hdr];

    if (hdr >= 0x100000000ULL) {
        g_dfBase = hdr;
        uint32_t mh[8] = {0};
        if (remote_read(hdr, mh, sizeof(mh))) {
            [out appendFormat:@"macho magic=0x%08x cputype=0x%08x filetype=%u ncmds=%u\n",
                              mh[0], mh[1], mh[3], mh[4]];
        } else {
            [out appendString:@"remote_read(header) FAILED\n"];
        }

        // read a few globals to prove the channel end-to-end
        const uint64_t slots[] = {
            0x15D89B40ULL,   // __bss start
            0x167B0E40ULL,   // __common start
        };
        for (int i = 0; i < 2; i++) {
            uint64_t v = 0;
            if (remote_read(hdr + slots[i], &v, 8)) {
                [out appendFormat:@"  slot base+0x%llx = 0x%llx\n", slots[i], v];
            } else {
                [out appendFormat:@"  slot base+0x%llx READ FAIL\n", slots[i]];
            }
        }
    }

    destroy_remote_call();
    [out appendString:@"\nDONE\n"];
    cyanide_log_sync(@"[DF] ===== probe done =====");
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
