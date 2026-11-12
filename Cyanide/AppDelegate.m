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
#import "kexploit/offsets.h"
#import <signal.h>
#import <sys/stat.h>
#import <unistd.h>
#include <stdlib.h>
#include <string.h>

// ===========================================================================
//  Delta Force (UE4.22, iOS ARM64) - vm_map guarded read
//
//  WHY:
//    kum_read() panics the kernel when a page-table entry is present but
//    bogus, which is what happened while scanning the heap blindly. The fix is
//    to never hand kum_read() an address that is not inside a region the
//    target's own vm_map reports as mapped:
//
//        proc -> task -> vm_map -> vm_map_entry list
//
//    VM.m already implements that walk (vm_map_iterate_entries). We collect
//    every [start,end) pair once, then guard every single read against it.
//    Out-of-region addresses are skipped, so an invalid PTE can never be
//    reached.
//
//  No RemoteCall / attach anywhere: that is what was killing the game.
// ===========================================================================

#define SEG_A_RVA   0x15D89B40ULL
#define SEG_A_SIZE  0x00800000ULL
#define SEG_B_RVA   0x167B0E40ULL
#define SEG_B_SIZE  0x002B43D0ULL

#define MOD_SIZE    0x16BFE1F0ULL
#define VT_LO_RVA   0x10B1F1C0ULL
#define VT_HI_RVA   0x15427A10ULL

#define MAX_REGIONS 8192
#define MAX_CAND    400

#define DF_MH_MAGIC_64  0xFEEDFACFu
#define DF_CPU_ARM64    0x0100000Cu
#define DF_MH_EXECUTE   2u

// implemented in TaskRop/VM.m
extern void vm_map_iterate_entries(uint64_t vm_map_ptr,
    void (^itBlock)(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop));

static uint64_t g_regStart[MAX_REGIONS];
static uint64_t g_regEnd[MAX_REGIONS];
static int      g_nReg = 0;

static uint64_t g_base = 0, g_modHi = 0, g_vtLo = 0, g_vtHi = 0;

// binary search over the sorted region list
static BOOL inRegion(uint64_t a, uint64_t len)
{
    if (!len) len = 1;
    if (a + len < a) return NO;
    int lo = 0, hi = g_nReg - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (a < g_regStart[mid]) hi = mid - 1;
        else if (a >= g_regEnd[mid]) lo = mid + 1;
        else return (a + len <= g_regEnd[mid]);
    }
    return NO;
}

// Every read goes through here.
static BOOL srd(uint64_t addr, void *dst, size_t len)
{
    if (!inRegion(addr, len)) return NO;
    return kum_read(addr, dst, len);
}

static int cmpU64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

static uint64_t srd64(uint64_t a)
{
    uint64_t v = 0;
    if (!srd(a, &v, 8)) return 0;
    return v;
}

static BOOL isHeapPtr(uint64_t v)
{
    if (v < g_modHi) return NO;
    if (v >= 0x8000000000ULL) return NO;
    if (v & 7) return NO;
    return YES;
}

static BOOL isObject(uint64_t addr)
{
    uint64_t vt = srd64(addr);
    if (!vt) return NO;
    return (vt >= g_vtLo && vt <= g_vtHi);
}

// TArray { Data, Num, Max } at [addr + off], read from an already-loaded block
static BOOL parseTArray(const uint8_t *blk, size_t blkLen, size_t off,
                        uint64_t *data, uint32_t *num, uint32_t *max)
{
    if (off + 0x10 > blkLen) return NO;
    uint64_t d; uint32_t n, m;
    memcpy(&d, blk + off, 8);
    memcpy(&n, blk + off + 8, 4);
    memcpy(&m, blk + off + 0xC, 4);
    if (!isHeapPtr(d)) return NO;
    if (n < 1 || n > 2000000) return NO;
    if (m < n || m > n * 2 + 4096) return NO;
    *data = d; *num = n; *max = m;
    return YES;
}

static uint64_t findBase(void)
{
    uint32_t mh[8];
    for (int i = 0; i < g_nReg; i++) {
        uint64_t s = g_regStart[i];
        uint64_t lim = s + 0x40000;
        if (lim > g_regEnd[i]) lim = g_regEnd[i];
        for (uint64_t va = s; va + 32 <= lim; va += 0x4000) {
            if (!srd(va, mh, sizeof(mh))) continue;
            if (mh[0] != DF_MH_MAGIC_64) continue;
            if (mh[1] != DF_CPU_ARM64) continue;
            if (mh[3] != DF_MH_EXECUTE) continue;
            return va;
        }
    }
    return 0;
}

NSString *df_scan_collect(void)
{
    NSMutableString *out = [NSMutableString stringWithCapacity:16384];
    cyanide_log_sync(@"[DF] ===== vm_map guarded scan =====");

    if (!settings_ensure_kernel_ready()) return @"kernel r/w not ready";

    static proc_entry_t ents[512];
    int n = proc_list_all(ents, 512);
    if (n <= 0) return @"cannot read proc list";

    uint64_t procAddr = 0;
    int pid = 0;
    char nm[PROC_NAME_MAX];
    memset(nm, 0, sizeof(nm));
    for (int i = 0; i < n; i++) {
        char low[PROC_NAME_MAX];
        int j = 0;
        const char *s = ents[i].name;
        for (; s[j] && j < PROC_NAME_MAX - 1; j++) {
            char c = s[j];
            low[j] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        low[j] = 0;
        if (!procAddr && (strstr(low, "delta") || strstr(low, "dfm"))) {
            procAddr = ents[i].proc;
            pid = (int)ents[i].pid;
            strncpy(nm, s, PROC_NAME_MAX - 1);
        }
    }
    if (!procAddr) return @"DeltaForceClient not running";
    [out appendFormat:@"target = %s pid=%d proc=0x%llx\n", nm, pid, procAddr];

    if (!kum_prepare(procAddr)) return @"kum_prepare FAILED";

    // ---- enumerate the target's real mapped regions ----
    uint64_t task = proc_task(procAddr);
    uint64_t vmMap = task ? task_get_vm_map(task) : 0;
    [out appendFormat:@"task=0x%llx vm_map=0x%llx\n", task, vmMap];
    if (!vmMap) return @"no vm_map";

    g_nReg = 0;
    vm_map_iterate_entries(vmMap, ^(uint64_t s, uint64_t e, uint64_t entry, BOOL *stop) {
        if (e <= s) return;
        if (s >= 0x8000000000ULL) return;                 // not user space
        if ((e - s) > 0x100000000ULL) return;             // bogus / implausible
        if (g_nReg < MAX_REGIONS) {
            g_regStart[g_nReg] = s;
            g_regEnd[g_nReg] = e;
            g_nReg++;
        }
    });

    uint64_t mapped = 0;
    for (int i = 0; i < g_nReg; i++) mapped += (g_regEnd[i] - g_regStart[i]);
    [out appendFormat:@"regions=%d  mapped=%.1f MB\n", g_nReg, mapped / 1048576.0];
    cyanide_log_sync(@"[DF] regions=%d mapped=%.1fMB", g_nReg, mapped / 1048576.0);

    // show the biggest ones for context
    for (int i = 0; i < g_nReg && i < 6; i++) {
        [out appendFormat:@"  [0x%llx, 0x%llx)  %.1f MB\n",
                          g_regStart[i], g_regEnd[i],
                          (g_regEnd[i] - g_regStart[i]) / 1048576.0];
    }
    [out appendString:@"\n"];

    if (g_nReg < 4) return @"vm_map walk produced too few regions";

    // ---- base ----
    g_base = findBase();
    if (!g_base) { [out appendString:@"main exec not found\n"]; return out; }
    g_modHi = g_base + MOD_SIZE;
    g_vtLo = g_base + VT_LO_RVA;
    g_vtHi = g_base + VT_HI_RVA;
    [out appendFormat:@"base 0x%llx\nvtable [0x%llx, 0x%llx]\n",
                      g_base, g_vtLo, g_vtHi];

    // ---- read __bss + __common (guarded) ----
    uint64_t total = SEG_A_SIZE + SEG_B_SIZE;
    uint8_t *buf = (uint8_t *)malloc((size_t)total);
    if (!buf) return @"oom";
    memset(buf, 0, (size_t)total);

    const uint64_t PAGE = 0x4000;
    uint64_t off = 0, ok = 0;
    int skipped = 0;
    while (off < total) {
        uint64_t len = total - off;
        if (len > PAGE) len = PAGE;
        uint64_t rva = (off < SEG_A_SIZE) ? (SEG_A_RVA + off)
                                          : (SEG_B_RVA + (off - SEG_A_SIZE));
        if (srd(g_base + rva, buf + off, (size_t)len)) ok += len;
        else ++skipped;
        off += len;
    }
    [out appendFormat:@"read ok=%llu/%llu skipped_pages=%d\n\n", ok, total, skipped];
    cyanide_log_sync(@"[DF] read ok=%llu skipped=%d", ok, skipped);

    // ---- collect heap pointers from the dump ----
    size_t nslots = (size_t)(off / 8);
    uint64_t *slots = (uint64_t *)malloc(nslots * 8);
    if (!slots) { free(buf); return @"oom2"; }
    size_t ns = 0;
    for (size_t i = 0; i < nslots; i++) {
        uint64_t v;
        memcpy(&v, buf + i * 8, 8);
        if (isHeapPtr(v)) slots[ns++] = v;
    }
    [out appendFormat:@"heap-pointer slots = %zu\n", ns];

    // ---- verify objects: probe EVERY slot (reads are region-guarded) ----
    uint64_t *objs = (uint64_t *)malloc(sizeof(uint64_t) * ns);
    if (!objs) { free(slots); free(buf); return @"oom2"; }
    size_t no = 0;
    for (size_t i = 0; i < ns; i++) {
        uint64_t c = slots[i];
        if (!isObject(c)) continue;
        objs[no++] = c;
    }
    // dedupe by sort
    qsort(objs, no, 8, cmpU64);
    size_t nu2 = 0;
    for (size_t i = 0; i < no; i++)
        if (i == 0 || objs[i] != objs[i-1]) objs[nu2++] = objs[i];
    no = nu2;

    [out appendFormat:@"verified UObjects = %zu\n", no];
    cyanide_log_sync(@"[DF] objects=%zu", no);

    // ---- find UWorld: object with a TArray whose first element is an object
    //      that has an Actors TArray at +0x28 ----
    uint64_t world = 0, levelsData = 0;
    static uint8_t blk[0x680];
    static int offHist[256];
    memset(offHist, 0, sizeof(offHist));
    int arrHits = 0, objWithArr = 0;

    for (size_t i = 0; i < no && !world; i++) {
        uint64_t cand = objs[i];
        if (!srd(cand, blk, sizeof(blk))) continue;

        BOOL anyArr = NO;
        for (size_t o = 0x08; o + 0x10 <= sizeof(blk) && o <= 0x600; o += 8) {
            uint64_t d; uint32_t nn, mm;
            if (!parseTArray(blk, sizeof(blk), o, &d, &nn, &mm)) continue;
            if (nn > 100000) continue;

            ++arrHits;
            anyArr = YES;
            offHist[(o - 0x08) / 8]++;

            uint64_t lv = srd64(d);
            if (!isHeapPtr(lv)) continue;
            if (!isObject(lv)) continue;

            uint8_t lb[0x40];
            if (!srd(lv, lb, sizeof(lb))) continue;
            uint64_t data; uint32_t num, mx;
            if (!parseTArray(lb, sizeof(lb), 0x28, &data, &num, &mx)) continue;

            uint64_t a0 = srd64(data);
            if (!isHeapPtr(a0)) continue;

            world = cand; levelsData = d;
            [out appendFormat:@"WORLD 0x%llx levels@+0x%llx n=%u level0=0x%llx "
                              @"actors=0x%llx an=%u\n",
                              world, (unsigned long)o, nn, lv, data, num];
            break;
        }
        if (anyArr) ++objWithArr;
    }

    [out appendFormat:@"objects with >=1 TArray = %d, tarray matches = %d\n",
                      objWithArr, arrHits];
    [out appendString:@"offset histogram (top 10):\n"];
    for (int r = 0; r < 10; r++) {
        int bi = -1, bv = 0;
        for (int k = 0; k < 256; k++) if (offHist[k] > bv) { bv = offHist[k]; bi = k; }
        if (bi < 0) break;
        [out appendFormat:@"  +0x%03X  x%d\n", 0x08 + bi * 8, bv];
        offHist[bi] = 0;
    }
    [out appendString:@"\n"];

    if (!world) {
        [out appendFormat:@"\nNO UWorld among %zu objects\n", no];
        free(objs); free(slots); free(buf);
        return out;
    }

    // ---- GWorld slot ----
    for (size_t i = 0; i < nslots; i++) {
        uint64_t v;
        memcpy(&v, buf + i * 8, 8);
        if (v != world) continue;
        uint64_t rva = (i * 8 < SEG_A_SIZE) ? (SEG_A_RVA + i * 8)
                                            : (SEG_B_RVA + (i * 8 - SEG_A_SIZE));
        [out appendFormat:@"GWORLD_SLOT = base + 0x%llx\n", rva];
        cyanide_log_sync(@"[DF] GWORLD slot rva=0x%llx", rva);
    }

    // ---- level + actors ----
    {
        uint64_t lv = srd64(levelsData);
        uint8_t lb[0x40];
        if (srd(lv, lb, sizeof(lb))) {
            uint64_t data; uint32_t num, mx;
            if (parseTArray(lb, sizeof(lb), 0x28, &data, &num, &mx)) {
                [out appendFormat:@"ULevel 0x%llx Actors 0x%llx n=%u\n", lv, data, num];
                uint32_t shown = num < 10 ? num : 10;
                for (uint32_t k = 0; k < shown; k++)
                    [out appendFormat:@"  actor[%u]=0x%llx\n",
                                      k, srd64(data + (uint64_t)k * 8)];
            }
        }
    }

    free(objs); free(slots); free(buf);
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
