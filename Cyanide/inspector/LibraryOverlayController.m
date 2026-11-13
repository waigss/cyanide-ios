//
//  LibraryOverlayController.m
//  Cyanide
//
//  SpringBoard 悬浮窗：显示目标进程（默认 smoba）的库与基址。
//
//  窗口结构（全部用远程调用在 SpringBoard 里搭）：
//      UIWindow (level 999999)
//        ├─ UILabel   标题      "Cyanide · 库地址"
//        ├─ UILabel   "执行"
//        ├─ UISwitch  执行开关   <- 用户点它；本进程轮询 isOn 读取状态
//        └─ UILabel   正文      状态行 + 库列表
//
//  交互说明：远程 UI 无法绑定 target/action（block 不能跨进程创建），所以按钮用
//  UISwitch 实现 —— 它的 isOn 可以被本进程远程读出，读完再由本进程 setOn:animated:
//  复位。轮询间隔 0.6s，按下到响应不超过一秒。
//
//  所有远程调用串行跑在一条专用队列上，两个 RemoteCallSession（SpringBoard /
//  目标进程）通过 remote_call_with_session() 分时压栈，避免互相污染状态。
//

#import "LibraryOverlayController.h"

#import "../TaskRop/RemoteCall.h"
#import "../tweaks/remote_objc.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/kutils.h"
#import "../DSKeepAlive.h"
#import "../SettingsViewController.h"
#import "KernelUserMemory.h"
#import "CyanideLog.h"

#import <UIKit/UIKit.h>
#import <notify.h>
#import <stdlib.h>
#import <string.h>

static const char *kOverlayAssocKey = "cyanideLibraryOverlayWindow";
static const int kOverlayTitleTag = 0x43A1;
static const int kOverlayBodyTag = 0x43A2;
static const int kOverlaySwitchTag = 0x43A3;
static const int kOverlayRunLabelTag = 0x43A4;

static const NSTimeInterval kOverlayTickInterval = 0.6;
static const NSTimeInterval kOverlayRefreshInterval = 3.0;
static const NSTimeInterval kOverlayDylibDeadline = 15.0;
static const int kOverlayAttachTimeoutMS = 3000;
static const int kOverlayDylibCallTimeout = 2;

static const int kOverlayMaxThirdParty = 8;
static const int kOverlayMaxSystem = 12;

#pragma mark - 远程小工具

static uint64_t ov_nsstring(const char *utf8)
{
    if (!utf8) return 0;
    uint64_t cls = r_class("NSString");
    if (!r_is_objc_ptr(cls)) return 0;

    uint64_t buf = r_alloc_str(utf8);
    if (!buf) return 0;

    uint64_t allocated = r_msg(cls, r_sel("alloc"), 0, 0, 0, 0);
    uint64_t str = r_is_objc_ptr(allocated)
        ? r_msg(allocated, r_sel("initWithUTF8String:"), buf, 0, 0, 0)
        : 0;
    r_free(buf);
    return str;
}

static uint64_t ov_color(double white, double alpha)
{
    uint64_t cls = r_class("UIColor");
    if (!r_is_objc_ptr(cls)) return 0;
    return r_msg2_main_raw(cls, "colorWithWhite:alpha:",
                           &white, sizeof(white),
                           &alpha, sizeof(alpha),
                           NULL, 0,
                           NULL, 0);
}

static void ov_set_rect(uint64_t obj, const char *selName, CGRect rect)
{
    r_msg2_main_raw(obj, selName, &rect, sizeof(rect), NULL, 0, NULL, 0, NULL, 0);
}

static void ov_set_double(uint64_t obj, const char *selName, double value)
{
    r_msg2_main_raw(obj, selName, &value, sizeof(value), NULL, 0, NULL, 0, NULL, 0);
}

static NSString *ov_short_name(NSString *path, NSUInteger limit)
{
    NSString *name = path.lastPathComponent;
    if (name.length == 0) name = path.length > 0 ? path : @"（未知）";
    if (name.length > limit) name = [[name substringToIndex:limit] stringByAppendingString:@"…"];
    return name;
}

static BOOL ov_path_is_third_party(NSString *path)
{
    if (path.length == 0) return NO;
    if ([path hasPrefix:@"/var/"]) return YES;
    if ([path hasPrefix:@"/private/var/"]) return YES;
    if ([path hasPrefix:@"/Library/"]) return YES;
    return NO;
}

// 附着目标进程：先用精确 proc 地址命中，失败再换 MIG filter bypass。
static RemoteCallSession *ov_attach(NSString *name, uint64_t procAddr,
                                    int timeoutMS, BOOL allowBypassRetry)
{
    int attempts = allowBypassRetry ? 2 : 1;

    for (int attempt = 0; attempt < attempts; attempt++) {
        if (procAddr != 0) g_RC_targetProcOverride = procAddr;

        RemoteCallSession *session =
            [[RemoteCallSession alloc] initWithProcess:name
                                    useMigFilterBypass:(attempt == 1)
                               firstExceptionTimeoutMS:timeoutMS];

        // 成功时 init_remote_call 已经消费并清零；失败时要自己清，
        // 否则这个 override 会留给下一次别的进程的会话。
        BOOL ok = (session != nil);
        g_RC_targetProcOverride = 0;

        if (ok) return session;

        RemoteCallInitFailure failure = remote_call_last_init_failure();
        if (failure == RemoteCallInitFailureKRWUnavailable ||
            failure == RemoteCallInitFailureProcessMissing) {
            break;
        }
    }
    return nil;
}

#pragma mark -

@interface LibraryOverlayController ()

@property (nonatomic, copy) NSString *processName;
@property (nonatomic, assign) int pid;
@property (nonatomic, assign) uint64_t procAddr;

@property (nonatomic, assign, getter=isActive) BOOL active;
@property (nonatomic, assign) BOOL dismissed;
@property (nonatomic, assign) BOOL busy;
@property (nonatomic, assign) BOOL autoInitKernel;

@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, strong) RemoteCallSession *springboardSession;

@property (nonatomic, assign) uint64_t window;
@property (nonatomic, assign) uint64_t titleLabel;
@property (nonatomic, assign) uint64_t bodyLabel;
@property (nonatomic, assign) uint64_t runSwitch;
@property (nonatomic, assign) uint64_t switchLibList;
@property (nonatomic, assign) uint64_t switchChain;
@property (nonatomic, assign) uint64_t switchClose;

@property (nonatomic, assign) int frontmostToken;
@property (nonatomic, strong) dispatch_source_t timer;

@property (nonatomic, assign) CGSize screenSize;
@property (nonatomic, assign) NSTimeInterval lastRefreshAt;
@property (nonatomic, copy) NSString *lastListText;
@property (nonatomic, copy) NSString *statusLine;

@end

@implementation LibraryOverlayController

+ (instancetype)sharedOverlay
{
    static LibraryOverlayController *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[LibraryOverlayController alloc] init];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.cyanide.libraryoverlay", DISPATCH_QUEUE_SERIAL);
        _frontmostToken = -1;
        _statusLine = @"准备中…";
    }
    return self;
}

- (NSString *)activeProcessName { return self.active ? self.processName : nil; }

#pragma mark - 生命周期

- (void)autoStartForProcessName:(NSString *)processName
{
    [self startForProcessName:processName pid:0 procAddr:0];
}

- (void)startForProcessName:(NSString *)processName pid:(int)pid procAddr:(uint64_t)procAddr
{
    if (processName.length == 0) return;

    [self stop];

    self.processName = processName;
    self.pid = pid;
    self.procAddr = procAddr;
    self.active = YES;
    self.dismissed = NO;
    self.busy = NO;
    self.autoInitKernel = YES;
    self.lastListText = nil;
    self.lastRefreshAt = 0;
    self.statusLine = @"准备中…";
    self.screenSize = [UIScreen mainScreen].bounds.size;

    // 切到目标 App 后本进程要活着才能继续刷新，靠静音音频保活。
    ds_keepalive_apply_enabled(YES);

    __weak typeof(self) weakSelf = self;

    if (self.frontmostToken < 0) {
        int token = -1;
        notify_register_dispatch("com.apple.springboard.frontmostApplicationChanged",
                                 &token,
                                 dispatch_get_main_queue(), ^(int t) {
            (void)t;
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            // 前台切换时立刻补一轮，不等 3 秒轮询。
            self.lastRefreshAt = 0;
        });
        self.frontmostToken = token;
    }

    if (!self.timer) {
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.queue);
        if (timer) {
            dispatch_source_set_timer(timer,
                                      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(NSEC_PER_SEC)),
                                      (uint64_t)(kOverlayTickInterval * NSEC_PER_SEC),
                                      (uint64_t)(0.2 * NSEC_PER_SEC));
            dispatch_source_set_event_handler(timer, ^{
                __strong typeof(weakSelf) self = weakSelf;
                if (!self) return;
                [self tick];
            });
            dispatch_resume(timer);
            self.timer = timer;
        }
    }
}

- (void)stop
{
    BOOL hadSession = (self.springboardSession != nil);

    self.active = NO;
    self.autoInitKernel = NO;

    if (self.timer) {
        dispatch_source_cancel(self.timer);
        self.timer = nil;
    }

    if (self.frontmostToken >= 0) {
        notify_cancel(self.frontmostToken);
        self.frontmostToken = -1;
    }

    if (hadSession) {
        dispatch_sync(self.queue, ^{
            [self removeOverlayLocked];
        });
    }

    self.springboardSession = nil;
    self.processName = nil;
    self.lastListText = nil;
}

- (void)stopByUser
{
    [self stop];
    self.dismissed = YES;
}

#pragma mark - 主轮询

- (void)tick
{
    if (!self.active || self.busy) return;

    self.busy = YES;
    @try {
        // 窗口本身依赖内核读写（要在 SpringBoard 里开 RemoteCall 会话），
        // 所以没就绪时先尝试初始化，成功后再建窗。
        if (!self.springboardSession) {
            if (!kexploit_krw_ready()) {
                if (!self.autoInitKernel) return;
                [self setStatusLineLocked:@"正在初始化内核…"];
                BOOL ok = settings_ensure_kernel_ready();
                if (!ok) {
                    [self setStatusLineLocked:@"内核初始化失败，稍后自动重试…"];
                    return;
                }
                [self setStatusLineLocked:@"内核已就绪，正在挂载悬浮窗…"];
            }

            if (![self installOverlayLocked]) {
                [self setStatusLineLocked:@"悬浮窗挂载失败，稍后重试…"];
                return;
            }
            self.lastRefreshAt = 0;
        }

        [self pollRunSwitchLocked];

        NSTimeInterval now = CFAbsoluteTimeGetCurrent();
        if (now - self.lastRefreshAt >= kOverlayRefreshInterval) {
            self.lastRefreshAt = now;
            [self refreshLibrariesLocked];
        }
    } @finally {
        self.busy = NO;
    }
}

#pragma mark - 开关轮询

- (void)pollRunSwitchLocked
{
    if (!self.springboardSession) return;
    if (!r_is_objc_ptr(self.switchLibList) &&
        !r_is_objc_ptr(self.switchChain) &&
        !r_is_objc_ptr(self.switchClose)) return;

    __block BOOL pressedLibList = NO;
    __block BOOL pressedChain = NO;
    __block BOOL pressedClose = NO;

    uint64_t libSwitch = self.switchLibList;
    uint64_t chainSwitch = self.switchChain;
    uint64_t closeSwitch = self.switchClose;

    remote_call_with_session(self.springboardSession, ^{
        if (r_is_objc_ptr(libSwitch)) {
            if ((r_msg2_main(libSwitch, "isOn", 0, 0, 0, 0) & 0xff) != 0) {
                pressedLibList = YES;
                r_msg2_main(libSwitch, "setOn:animated:", 0, 0, 0, 0);
            }
        }
        if (r_is_objc_ptr(chainSwitch)) {
            if ((r_msg2_main(chainSwitch, "isOn", 0, 0, 0, 0) & 0xff) != 0) {
                pressedChain = YES;
                r_msg2_main(chainSwitch, "setOn:animated:", 0, 0, 0, 0);
            }
        }
        if (r_is_objc_ptr(closeSwitch)) {
            if ((r_msg2_main(closeSwitch, "isOn", 0, 0, 0, 0) & 0xff) != 0) {
                pressedClose = YES;
                r_msg2_main(closeSwitch, "setOn:animated:", 0, 0, 0, 0);
            }
        }
    });

    if (pressedClose) {
        cyanide_log(@"[OVERLAY] close requested");
        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter]
                postNotificationName:@"CyanideOverlayCloseRequested" object:nil];
        });
        return;
    }

    if (pressedLibList) {
        [self setStatusLineLocked:@"READ_LIBRARIES"];
        cyanide_log(@"[OVERLAY] action: read libraries");
        [self refreshLibrariesLocked];
    }

    if (pressedChain) {
        [self setStatusLineLocked:@"RUN_CHAIN"];
        cyanide_log(@"[OVERLAY] action: pointer chain");
        [self runPointerChainLocked];
    }
}

// 悬浮菜单里的指针链：主程序基址 + 0x16A627B0 → ptr → +0xF8 → ptr → +0x98 → ptr → +0xA8 int32
- (void)runPointerChainLocked
{
    if (!kexploit_krw_ready()) {
        [self setStatusLineLocked:@"内核未就绪"];
        return;
    }

    uint64_t base = 0;
    if (!kum_main_executable_base(&base)) {
        [self setStatusLineLocked:@"未找到主程序基址"];
        return;
    }

    uint64_t addr = base + 0x16A627B0ULL;
    uint8_t buf[8] = {0};

    uint64_t p1 = 0, p2 = 0, p3 = 0;
    if (!kum_read(addr, buf, 8)) { [self setStatusLineLocked:@"L1 未映射"]; return; }
    memcpy(&p1, buf, 8);

    if (!kum_read(p1 + 0xF8, buf, 8)) { [self setStatusLineLocked:@"L2 未映射"]; return; }
    memcpy(&p2, buf, 8);

    if (!kum_read(p2 + 0x98, buf, 8)) { [self setStatusLineLocked:@"L3 未映射"]; return; }
    memcpy(&p3, buf, 8);

    int32_t value = 0;
    if (!kum_read(p3 + 0xA8, &value, 4)) { [self setStatusLineLocked:@"L4 未映射"]; return; }

    NSString *text = [NSString stringWithFormat:
        @"base+0x16A627B0 = 0x%llx\n+0xF8 → 0x%llx\n+0x98 → 0x%llx\n+0xA8 = %d",
        (unsigned long long)p1, (unsigned long long)p2, (unsigned long long)p3, value];

    cyanide_log(@"[悬浮菜单] 指针链结果：%@", [text stringByReplacingOccurrencesOfString:@"\n" withString:@" | "]);

    self.lastListText = text;
    [self setStatusLineLocked:@"指针链读取完成"];
}

#pragma mark - 悬浮窗

- (BOOL)installOverlayLocked
{
    if (!kexploit_krw_ready()) return NO;

    if (!proc_self()) {
        kutils_reset_self_cache();
        return NO;
    }

    g_RC_targetProcOverride = 0;

    RemoteCallSession *session =
        [[RemoteCallSession alloc] initWithProcess:@"SpringBoard"
                               useMigFilterBypass:NO
                          firstExceptionTimeoutMS:12000];
    if (!session) return NO;

    self.springboardSession = session;

    __block BOOL ok = NO;
    __block uint64_t builtWindow = 0;
    __block uint64_t builtTitle = 0;
    __block uint64_t builtBody = 0;
    __block uint64_t builtSwitchLibList = 0;
    __block uint64_t builtSwitchChain = 0;
    __block uint64_t builtSwitchClose = 0;

    CGFloat screenW = MAX(200.0, self.screenSize.width);
    CGFloat screenH = MAX(320.0, self.screenSize.height);

    remote_call_with_session(session, ^{
        uint64_t UIApplication = r_class("UIApplication");
        uint64_t app = r_is_objc_ptr(UIApplication)
            ? r_msg2_main(UIApplication, "sharedApplication", 0, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(app)) return;

        uint64_t keyWindow = r_msg2_main(app, "keyWindow", 0, 0, 0, 0);
        if (!r_is_objc_ptr(keyWindow)) {
            uint64_t windows = r_msg2_main(app, "windows", 0, 0, 0, 0);
            uint64_t count = r_is_objc_ptr(windows)
                ? r_msg2_main(windows, "count", 0, 0, 0, 0) : 0;
            if (count > 0 && count < 64) {
                keyWindow = r_msg2_main(windows, "objectAtIndex:", 0, 0, 0, 0);
            }
        }
        if (!r_is_objc_ptr(keyWindow)) return;

        uint64_t scene = r_msg2_main(keyWindow, "windowScene", 0, 0, 0, 0);
        if (!r_is_objc_ptr(scene)) return;

        uint64_t UIWindowClass = r_class("UIWindow");
        uint64_t allocated = r_is_objc_ptr(UIWindowClass)
            ? r_msg2_main(UIWindowClass, "alloc", 0, 0, 0, 0) : 0;
        uint64_t window = r_is_objc_ptr(allocated)
            ? r_msg2_main(allocated, "initWithWindowScene:", scene, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(window)) return;

        // ImGui 风格：紧凑、深色、1px 边框
        CGFloat width = 240.0;
        CGFloat height = 24.0 + 3.0 * 34.0 + 44.0;
        CGRect windowRect = CGRectMake(16.0, 96.0, width, height);

        ov_set_rect(window, "setFrame:", windowRect);
        ov_set_double(window, "setWindowLevel:", 999999.0);
        r_msg2_main(window, "setUserInteractionEnabled:", 1, 0, 0, 0);

        uint64_t background = ov_color(0.11, 0.96);
        if (r_is_objc_ptr(background)) {
            r_msg2_main(window, "setBackgroundColor:", background, 0, 0, 0);
        }

        uint64_t layer = r_msg2_main(window, "layer", 0, 0, 0, 0);
        if (r_is_objc_ptr(layer)) {
            ov_set_double(layer, "setCornerRadius:", 4.0);
            r_msg2_main(layer, "setMasksToBounds:", 1, 0, 0, 0);
            ov_set_double(layer, "setBorderWidth:", 1.0);
            uint64_t border = ov_color(0.24, 1.0);
            if (r_is_objc_ptr(border)) {
                uint64_t cg = r_msg2_main(border, "CGColor", 0, 0, 0, 0);
                if (r_is_objc_ptr(cg)) r_msg2_main(layer, "setBorderColor:", cg, 0, 0, 0);
            }
        }

        uint64_t UILabelClass = r_class("UILabel");
        uint64_t UIFontClass = r_class("UIFont");
        uint64_t UIColorClass = r_class("UIColor");
        if (!r_is_objc_ptr(UILabelClass) || !r_is_objc_ptr(UIFontClass)) return;

        uint64_t white = r_is_objc_ptr(UIColorClass)
            ? r_msg2_main(UIColorClass, "whiteColor", 0, 0, 0, 0) : 0;
        uint64_t gray = r_is_objc_ptr(UIColorClass)
            ? r_msg2_main_raw(UIColorClass, "colorWithWhite:alpha:",
                              &(double){0.62}, sizeof(double),
                              &(double){1.0}, sizeof(double),
                              NULL, 0, NULL, 0) : 0;

        // 标题栏
        uint64_t titleAllocated = r_msg2_main(UILabelClass, "alloc", 0, 0, 0, 0);
        uint64_t title = r_is_objc_ptr(titleAllocated)
            ? r_msg2_main(titleAllocated, "init", 0, 0, 0, 0) : 0;
        if (r_is_objc_ptr(title)) {
            r_msg2_main(title, "setTag:", kOverlayTitleTag, 0, 0, 0);
            double titleSize = 11.0;
            uint64_t font = r_msg2_main_raw(UIFontClass, "monospacedSystemFontOfSize:weight:",
                                            &titleSize, sizeof(titleSize),
                                            &(double){0.5}, sizeof(double),
                                            NULL, 0, NULL, 0);
            if (r_is_objc_ptr(font)) r_msg2_main(title, "setFont:", font, 0, 0, 0);
            if (r_is_objc_ptr(white)) r_msg2_main(title, "setTextColor:", white, 0, 0, 0);
            ov_set_rect(title, "setFrame:", CGRectMake(8.0, 4.0, width - 16.0, 18.0));
            uint64_t str = ov_nsstring("Cyanide · 悬浮菜单");
            if (r_is_objc_ptr(str)) r_msg2_main(title, "setText:", str, 0, 0, 0);
            r_msg2_main(window, "addSubview:", title, 0, 0, 0);
            builtTitle = title;
        }

        // 三行开关
        const char *rowTitles[3] = {"读取库列表", "执行指针链", "关闭悬浮窗"};

        uint64_t switchClass = r_class("UISwitch");

        for (int i = 0; i < 3; i++) {
            CGFloat y = 24.0 + i * 34.0;

            uint64_t rowAllocated = r_msg2_main(UILabelClass, "alloc", 0, 0, 0, 0);
            uint64_t rowLabel = r_is_objc_ptr(rowAllocated)
                ? r_msg2_main(rowAllocated, "init", 0, 0, 0, 0) : 0;
            if (r_is_objc_ptr(rowLabel)) {
                double rowSize = 12.0;
                uint64_t rowFont = r_msg2_main_raw(UIFontClass, "monospacedSystemFontOfSize:weight:",
                                                   &rowSize, sizeof(rowSize),
                                                   &(double){0.0}, sizeof(double),
                                                   NULL, 0, NULL, 0);
                if (r_is_objc_ptr(rowFont)) r_msg2_main(rowLabel, "setFont:", rowFont, 0, 0, 0);
                if (r_is_objc_ptr(white)) r_msg2_main(rowLabel, "setTextColor:", white, 0, 0, 0);
                ov_set_rect(rowLabel, "setFrame:", CGRectMake(10.0, y + 6.0, width - 70.0, 18.0));
                uint64_t str = ov_nsstring(rowTitles[i]);
                if (r_is_objc_ptr(str)) r_msg2_main(rowLabel, "setText:", str, 0, 0, 0);
                r_msg2_main(window, "addSubview:", rowLabel, 0, 0, 0);
            }

            uint64_t switchAllocated = r_is_objc_ptr(switchClass)
                ? r_msg2_main(switchClass, "alloc", 0, 0, 0, 0) : 0;
            uint64_t rowSwitch = r_is_objc_ptr(switchAllocated)
                ? r_msg2_main(switchAllocated, "init", 0, 0, 0, 0) : 0;
            if (r_is_objc_ptr(rowSwitch)) {
                r_msg2_main(rowSwitch, "setTag:", kOverlaySwitchTag + i, 0, 0, 0);
                r_msg2_main(rowSwitch, "setOn:", 0, 0, 0, 0);
                ov_set_rect(rowSwitch, "setFrame:", CGRectMake(width - 58.0, y, 52.0, 30.0));
                r_msg2_main(window, "addSubview:", rowSwitch, 0, 0, 0);
                if (i == 0) builtSwitchLibList = rowSwitch;
                else if (i == 1) builtSwitchChain = rowSwitch;
                else builtSwitchClose = rowSwitch;
            }
        }

        // 状态行
        uint64_t bodyAllocated = r_msg2_main(UILabelClass, "alloc", 0, 0, 0, 0);
        uint64_t body = r_is_objc_ptr(bodyAllocated)
            ? r_msg2_main(bodyAllocated, "init", 0, 0, 0, 0) : 0;
        if (r_is_objc_ptr(body)) {
            r_msg2_main(body, "setTag:", kOverlayBodyTag, 0, 0, 0);
            r_msg2_main(body, "setNumberOfLines:", 2, 0, 0, 0);
            double bodySize = 10.0;
            uint64_t bodyFont = r_msg2_main_raw(UIFontClass, "monospacedSystemFontOfSize:weight:",
                                                &bodySize, sizeof(bodySize),
                                                &(double){0.0}, sizeof(double),
                                                NULL, 0, NULL, 0);
            if (r_is_objc_ptr(bodyFont)) r_msg2_main(body, "setFont:", bodyFont, 0, 0, 0);
            if (r_is_objc_ptr(gray)) r_msg2_main(body, "setTextColor:", gray, 0, 0, 0);
            ov_set_rect(body, "setFrame:", CGRectMake(10.0, 24.0 + 3.0 * 34.0, width - 20.0, 34.0));
            r_msg2_main(window, "addSubview:", body, 0, 0, 0);
            builtBody = body;
        }

        r_msg2_main(window, "setHidden:", 0, 0, 0, 0);

        uint64_t key = r_sel(kOverlayAssocKey);
        if (key) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject",
                         app, key, window, 1, 0, 0, 0, 0);
        }

        builtWindow = window;
        ok = YES;
    });

    self.window = builtWindow;
    self.titleLabel = builtTitle;
    self.bodyLabel = builtBody;
    self.switchLibList = builtSwitchLibList;
    self.switchChain = builtSwitchChain;
    self.switchClose = builtSwitchClose;

    if (!ok) {
        self.springboardSession = nil;
        return NO;
    }

    [self setStatusLineLocked:@"就绪：拨动开关执行对应动作"];
    return YES;
}

- (void)removeOverlayLocked
{
    if (!self.springboardSession) {
        self.window = 0;
        self.titleLabel = 0;
        self.bodyLabel = 0;
        self.switchLibList = 0;
        self.switchChain = 0;
        self.switchClose = 0;
        return;
    }

    uint64_t window = self.window;

    remote_call_with_session(self.springboardSession, ^{
        if (!r_is_objc_ptr(window)) return;

        r_msg2_main(window, "setHidden:", 1, 0, 0, 0);
        r_msg2_main(window, "removeFromSuperview", 0, 0, 0, 0);

        uint64_t app = r_msg2_main(r_class("UIApplication"), "sharedApplication", 0, 0, 0, 0);
        uint64_t key = r_sel(kOverlayAssocKey);
        if (r_is_objc_ptr(app) && key) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject",
                         app, key, 0, 1, 0, 0, 0, 0);
        }
    });

    self.window = 0;
    self.titleLabel = 0;
    self.bodyLabel = 0;
    self.switchLibList = 0;
    self.switchChain = 0;
    self.switchClose = 0;
}

- (void)setStatusLineLocked:(NSString *)line
{
    self.statusLine = line ?: @"";
    [self pushBodyTextLocked];
}

- (void)pushBodyTextLocked
{
    if (!self.springboardSession || !r_is_objc_ptr(self.bodyLabel)) return;

    NSMutableString *text = [NSMutableString string];
    [text appendFormat:@"目标 %@（PID %d）\n", self.processName ?: @"?", self.pid];
    [text appendString:self.statusLine ?: @""];

    const char *utf8 = text.UTF8String;
    if (!utf8) return;

    remote_call_with_session(self.springboardSession, ^{
        uint64_t str = ov_nsstring(utf8);
        if (r_is_objc_ptr(str)) {
            r_msg2_main(self.bodyLabel, "setText:", str, 0, 0, 0);
        }
    });
}

#pragma mark - 目标定位

// 按名字在内核进程表里找目标，顺便拿到精确的 struct proc 地址。
- (BOOL)lookupTargetLocked
{
    if (!kexploit_krw_ready()) return NO;
    if (self.processName.length == 0) return NO;

    const char *want = self.processName.UTF8String;
    if (!want) return NO;

    const int capacity = 1024;
    proc_entry_t *buffer = calloc((size_t)capacity, sizeof(proc_entry_t));
    if (!buffer) return NO;

    int count = proc_list_all(buffer, capacity);
    BOOL found = NO;

    for (int i = 0; i < count; i++) {
        if (strcmp(buffer[i].name, want) != 0) continue;
        self.procAddr = buffer[i].proc;
        self.pid = (int)buffer[i].pid;
        found = YES;
        break;
    }

    free(buffer);
    return found;
}

#pragma mark - 读库

- (void)refreshLibrariesLocked
{
    if (!kexploit_krw_ready()) {
        [self setStatusLineLocked:@"KERNEL_NOT_READY"];
        return;
    }

    if (!proc_self()) {
        kutils_reset_self_cache();
        [self setStatusLineLocked:@"KERNEL_SESSION_BUILDING"];
        return;
    }

    if (![self lookupTargetLocked]) {
        self.lastListText = nil;
        [self setStatusLineLocked:[NSString stringWithFormat:@"TARGET_NOT_FOUND %@",
                                   self.processName ?: @"?"]];
        return;
    }

    // Kernel direct read first: no attach, no threads, works while target is suspended.
    NSArray<NSDictionary<NSString *, id> *> *rows = nil;
    NSString *error = nil;

    if (kum_prepare(self.procAddr)) {
        rows = kum_read_dyld_images(&error);
    } else {
        error = @"KUM_PREPARE_FAILED";
    }

    if (rows.count > 0) {
        NSMutableString *text = [NSMutableString string];
        [text appendFormat:@"TOTAL %lu (kernel-direct)\n", (unsigned long)rows.count];

        NSUInteger shown = 0;
        for (NSDictionary *row in rows) {
            if (shown >= 10) break;
            [text appendFormat:@"0x%llx %@\n",
             [row[@"base"] unsignedLongLongValue], row[@"name"]];
            shown += 1;
        }
        if (rows.count > shown) {
            [text appendFormat:@"... +%lu\n", (unsigned long)(rows.count - shown)];
        }

        self.lastListText = text;
        [self setStatusLineLocked:[NSString stringWithFormat:@"READ %lu MODULES",
                                   (unsigned long)rows.count]];
        cyanide_log(@"[OVERLAY] kernel direct read ok: %lu modules", (unsigned long)rows.count);
        return;
    }

    cyanide_log(@"[OVERLAY] kernel direct read failed: %@", error ?: @"unknown");

    uint64_t base = 0;
    if (kum_main_executable_base(&base)) {
        self.lastListText = [NSString stringWithFormat:@"MAIN BASE 0x%llx\n%@",
                             (unsigned long long)base, error ?: @"unknown"];
        [self setStatusLineLocked:@"MAIN_BASE_ONLY"];
        return;
    }

    [self setStatusLineLocked:(error ?: @"READ_FAILED")];
}

@end
