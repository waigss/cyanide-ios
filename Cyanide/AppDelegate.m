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
//  Delta Force (UE4.22, iOS ARM64) - DIAGNOSE + SAFE DUMP
//
//  Step 1: read the target's dyld image list. That gives the real main
//          executable base instead of guessing by scanning for a Mach-O magic
//          (the previous guess landed on some dylib, so every RVA was off and
//          almost every read hit an unmapped page).
//  Step 2: validate the Mach-O header at that base.
//  Step 3: only if validation passes, dump two known regions to Documents/.
//
//  No pointer is ever dereferenced.
// ===========================================================================

#define SEG_A_RVA   0x15D89B40ULL   // __bss start
#define SEG_A_SIZE  0x00800000ULL   // first 8 MB only

#define SEG_B_RVA   0x167B0E40ULL   // __common
#define SEG_B_SIZE  0x002B43D0ULL

#define DF_MOD_SIZE 0x16BFE1F0ULL

static uint64_t g_dfSlide = 0;

static uint64_t dfDumpSegment(NSString *name, uint64_t rva, uint64_t size,
                              NSMutableString *out)
{
    const uint64_t PAGE = 0x4000;
    uint8_t *buf = (uint8_t *)malloc((size_t)size);
    if (!buf) {
        cyanide_log_sync(@"[DF] %@ malloc failed", name);
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
    [out appendFormat:@"%@: %@  ok=%llu/%llu  unmapped_pages=%d\n",
                      name, w ? @"ok" : @"FAIL", okBytes, size, failPages];
    return okBytes;
}

NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:8192];
    cyanide_log_sync(@"[DF] ===== diagnose begin =====");

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

    [out appendFormat:@"map    = [0x%llx, 0x%llx]\n",
                      kum_map_min(), kum_map_max()];

    // ---- 1) real module list from dyld ----
    NSString *err = nil;
    NSArray<NSDictionary<NSString *, id> *> *imgs = kum_read_dyld_images(&err);
    if (!imgs) {
        [out appendFormat:@"dyld images FAILED: %@\n", err ?: @"?"];
        return out;
    }

    [out appendFormat:@"dyld images = %lu\n", (unsigned long)imgs.count];
    for (NSUInteger i = 0; i < imgs.count && i < 40; i++) {
        NSDictionary *d = imgs[i];
        [out appendFormat:@"  [%lu] %@  0x%llx  %@\n",
                          (unsigned long)i,
                          d[@"name"] ?: @"?",
                          [d[@"base"] unsignedLongLongValue],
                          d[@"path"] ?: @""];
    }

    // ---- 2) pick the main executable ----
    // Order of preference:
    //   a) path ends with "/<process name>"   (the app binary itself)
    //   b) inside Foo.app/ but not Frameworks/
    //   c) image 0
    NSString *procName = [NSString stringWithUTF8String:targetName];
    NSString *suffix = [NSString stringWithFormat:@"/%@", procName];

    uint64_t base = 0;
    NSString *baseName = nil;

    for (NSDictionary *d in imgs) {
        NSString *pth = d[@"path"] ?: @"";
        if ([pth hasSuffix:suffix]) {
            base = [d[@"base"] unsignedLongLongValue];
            baseName = d[@"name"];
            break;
        }
    }
    if (!base) {
        for (NSDictionary *d in imgs) {
            NSString *pth = d[@"path"] ?: @"";
            if ([pth containsString:@".app/"] &&
                ![pth containsString:@"/Frameworks/"]) {
                base = [d[@"base"] unsignedLongLongValue];
                baseName = d[@"name"];
                break;
            }
        }
    }
    if (!base) {
        base = [imgs.firstObject[@"base"] unsignedLongLongValue];
        baseName = imgs.firstObject[@"name"];
    }
    if (base < 0x100000000ULL) {
        [out appendString:@"no usable base\n"];
        return out;
    }

    g_dfSlide = base;
    [out appendFormat:@"\nchosen base = 0x%llx  (%@)\n", base, baseName ?: @"?"];
    cyanide_log_sync(@"[DF] base=0x%llx name=%@", base, baseName);

    // ---- 3) validate the Mach-O header ----
    uint32_t mh[8] = {0};
    BOOL mhOk = kum_read(base, mh, sizeof(mh));
    if (!mhOk) {
        [out appendString:@"macho header unreadable\n"];
        return out;
    }
    [out appendFormat:@"macho magic=0x%08x cputype=0x%08x filetype=%u ncmds=%u sizeofcmds=0x%x\n",
                      mh[0], mh[1], mh[3], mh[4], mh[5]];

    BOOL plausible = (mh[0] == 0xFEEDFACF) && (mh[1] == 0x0100000C) &&
                     (mh[3] == 2) && (mh[4] > 16 && mh[4] < 4096);
    if (!plausible) {
        [out appendString:@"\nMach-O header NOT plausible -> skipping dump\n"];
        cyanide_log_sync(@"[DF] base rejected");
        return out;
    }

    [out appendFormat:@"\nA = 0x%llx  %llu bytes\n", base + SEG_A_RVA, SEG_A_SIZE];
    [out appendFormat:@"B = 0x%llx  %llu bytes\n\n", base + SEG_B_RVA, SEG_B_SIZE];

    // ---- 4) dump ----
    uint64_t a = dfDumpSegment(@"df_a", SEG_A_RVA, SEG_A_SIZE, out);
    uint64_t b = dfDumpSegment(@"df_b", SEG_B_RVA, SEG_B_SIZE, out);

    NSString *info = [NSString stringWithFormat:
        @"base=0x%llx\nbase_name=%@\n"
        @"map_min=0x%llx\nmap_max=0x%llx\n"
        @"macho_magic=0x%08x\nmacho_cputype=0x%08x\nmacho_filetype=%u\nmacho_ncmds=%u\n"
        @"A_rva=0x%llx\nA_size=%llu\nA_ok=%llu\n"
        @"B_rva=0x%llx\nB_size=%llu\nB_ok=%llu\n",
        base, baseName ?: @"?",
        kum_map_min(), kum_map_max(),
        mh[0], mh[1], mh[3], mh[4],
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
