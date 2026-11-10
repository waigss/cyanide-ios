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
    if (!r_is_objc_ptr(self.runSwitch) || !self.springboardSession) return;

    __block BOOL pressed = NO;
    remote_call_with_session(self.springboardSession, ^{
        pressed = (r_msg2_main(self.runSwitch, "isOn", 0, 0, 0, 0) & 0xff) != 0;
        if (pressed) {
            // 由本进程复位，用户看到的是一个会自动弹回的开关。
            r_msg2_main(self.runSwitch, "setOn:animated:", 0, 0, 0, 0);
        }
    });

    if (!pressed) return;

    [self setStatusLineLocked:@"已按下：正在初始化内核并查找目标…"];

    BOOL ok = settings_ensure_kernel_ready();
    if (!ok) {
        [self setStatusLineLocked:@"内核初始化失败，详见 Cyanide 的 Log 页"];
        return;
    }

    // 重新按名字定位，避免用旧的 proc 地址。
    self.procAddr = 0;
    self.pid = 0;
    self.lastRefreshAt = CFAbsoluteTimeGetCurrent();
    [self refreshLibrariesLocked];
}

#pragma mark - 悬浮窗

- (BOOL)installOverlayLocked
{
    if (!kexploit_krw_ready()) return NO;

    // proc_self() 还没解析出来时，proc_find_by_name() 会直接返回 0，
    // init_remote_call 只会打一行 "process not found or invalid ... proc=0"。
    // 与其打噪音日志，不如这一轮直接跳过，下一拍重新解析。
    if (!proc_self()) {
        kutils_reset_self_cache();
        return NO;
    }

    // 上一次给目标进程设置的 override 绝不能被 SpringBoard 会话消费掉，
    // 否则会把 remote call 的线程开进目标 App 里。
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
    __block uint64_t builtSwitch = 0;

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

        // 这个窗口会吃掉它覆盖区域内的触摸，所以别开太大，
        // 保住屏幕下半部分仍然可以正常操作目标 App。
        CGFloat width = MIN(MAX(240.0, screenW - 16.0), 380.0);
        CGFloat height = MIN(screenH * 0.34, 330.0);
        CGRect windowRect = CGRectMake(8.0, 56.0, width, height);

        ov_set_rect(window, "setFrame:", windowRect);
        ov_set_double(window, "setWindowLevel:", 999999.0);
        r_msg2_main(window, "setUserInteractionEnabled:", 1, 0, 0, 0);

        uint64_t background = ov_color(0.0, 0.85);
        if (r_is_objc_ptr(background)) {
            r_msg2_main(window, "setBackgroundColor:", background, 0, 0, 0);
        }

        uint64_t UILabelClass = r_class("UILabel");
        uint64_t UIFontClass = r_class("UIFont");
        uint64_t UIColorClass = r_class("UIColor");
        if (!r_is_objc_ptr(UILabelClass) || !r_is_objc_ptr(UIFontClass)) return;

        uint64_t whiteColor = r_is_objc_ptr(UIColorClass)
            ? r_msg2_main(UIColorClass, "whiteColor", 0, 0, 0, 0) : 0;

        // 标题
        uint64_t titleAllocated = r_msg2_main(UILabelClass, "alloc", 0, 0, 0, 0);
        uint64_t title = r_is_objc_ptr(titleAllocated)
            ? r_msg2_main(titleAllocated, "init", 0, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(title)) return;

        r_msg2_main(title, "setTag:", kOverlayTitleTag, 0, 0, 0);
        double titleSize = 11.0;
        double bold = 0.4;
        uint64_t titleFont = r_msg2_main_raw(UIFontClass, "systemFontOfSize:weight:",
                                             &titleSize, sizeof(titleSize),
                                             &bold, sizeof(bold),
                                             NULL, 0, NULL, 0);
        if (r_is_objc_ptr(titleFont)) r_msg2_main(title, "setFont:", titleFont, 0, 0, 0);
        if (r_is_objc_ptr(whiteColor)) r_msg2_main(title, "setTextColor:", whiteColor, 0, 0, 0);
        ov_set_rect(title, "setFrame:", CGRectMake(10.0, 6.0, width - 130.0, 18.0));
        uint64_t titleStr = ov_nsstring("Cyanide · 库地址");
        if (r_is_objc_ptr(titleStr)) r_msg2_main(title, "setText:", titleStr, 0, 0, 0);
        r_msg2_main(window, "addSubview:", title, 0, 0, 0);

        // 「执行」标签
        uint64_t runAllocated = r_msg2_main(UILabelClass, "alloc", 0, 0, 0, 0);
        uint64_t runLabel = r_is_objc_ptr(runAllocated)
            ? r_msg2_main(runAllocated, "init", 0, 0, 0, 0) : 0;
        if (r_is_objc_ptr(runLabel)) {
            r_msg2_main(runLabel, "setTag:", kOverlayRunLabelTag, 0, 0, 0);
            double runSize = 11.0;
            uint64_t runFont = r_msg2_main_raw(UIFontClass, "systemFontOfSize:",
                                               &runSize, sizeof(runSize),
                                               NULL, 0, NULL, 0, NULL, 0);
            if (r_is_objc_ptr(runFont)) r_msg2_main(runLabel, "setFont:", runFont, 0, 0, 0);
            if (r_is_objc_ptr(whiteColor)) r_msg2_main(runLabel, "setTextColor:", whiteColor, 0, 0, 0);
            ov_set_rect(runLabel, "setFrame:", CGRectMake(width - 120.0, 8.0, 44.0, 16.0));
            uint64_t runText = ov_nsstring("执行");
            if (r_is_objc_ptr(runText)) r_msg2_main(runLabel, "setText:", runText, 0, 0, 0);
            r_msg2_main(window, "addSubview:", runLabel, 0, 0, 0);
        }

        // 执行开关
        uint64_t switchClass = r_class("UISwitch");
        uint64_t switchAllocated = r_is_objc_ptr(switchClass)
            ? r_msg2_main(switchClass, "alloc", 0, 0, 0, 0) : 0;
        uint64_t runSwitch = r_is_objc_ptr(switchAllocated)
            ? r_msg2_main(switchAllocated, "init", 0, 0, 0, 0) : 0;
        if (r_is_objc_ptr(runSwitch)) {
            r_msg2_main(runSwitch, "setTag:", kOverlaySwitchTag, 0, 0, 0);
            r_msg2_main(runSwitch, "setOn:", 0, 0, 0, 0);
            ov_set_rect(runSwitch, "setFrame:", CGRectMake(width - 74.0, 0.0, 64.0, 32.0));
            r_msg2_main(window, "addSubview:", runSwitch, 0, 0, 0);
            builtSwitch = runSwitch;
        }

        // 正文
        uint64_t bodyAllocated = r_msg2_main(UILabelClass, "alloc", 0, 0, 0, 0);
        uint64_t body = r_is_objc_ptr(bodyAllocated)
            ? r_msg2_main(bodyAllocated, "init", 0, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(body)) return;

        r_msg2_main(body, "setTag:", kOverlayBodyTag, 0, 0, 0);
        r_msg2_main(body, "setNumberOfLines:", 0, 0, 0, 0);
        double bodySize = 9.0;
        double regular = 0.0;
        uint64_t bodyFont = r_msg2_main_raw(UIFontClass, "monospacedSystemFontOfSize:weight:",
                                            &bodySize, sizeof(bodySize),
                                            &regular, sizeof(regular),
                                            NULL, 0, NULL, 0);
        if (r_is_objc_ptr(bodyFont)) r_msg2_main(body, "setFont:", bodyFont, 0, 0, 0);
        if (r_is_objc_ptr(whiteColor)) r_msg2_main(body, "setTextColor:", whiteColor, 0, 0, 0);
        ov_set_rect(body, "setFrame:", CGRectMake(10.0, 40.0, width - 20.0, height - 50.0));

        r_msg2_main(window, "addSubview:", body, 0, 0, 0);
        r_msg2_main(window, "setHidden:", 0, 0, 0, 0);

        uint64_t key = r_sel(kOverlayAssocKey);
        if (key) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject",
                         app, key, window, 1, 0, 0, 0, 0);
        }

        builtWindow = window;
        builtTitle = title;
        builtBody = body;
        ok = YES;
    });

    self.window = builtWindow;
    self.titleLabel = builtTitle;
    self.bodyLabel = builtBody;
    self.runSwitch = builtSwitch;

    if (!ok) {
        self.springboardSession = nil;
        return NO;
    }

    [self setStatusLineLocked:@"就绪：按右上角「执行」初始化内核并读取目标"];
    return YES;
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
    [text appendFormat:@"目标: %@%@\n", self.processName ?: @"?",
     self.pid > 0 ? [NSString stringWithFormat:@" (PID %d)", self.pid] : @""];
    [text appendFormat:@"%@\n", self.statusLine ?: @""];

    if (self.lastListText.length > 0) {
        [text appendString:@"\n"];
        [text appendString:self.lastListText];
    }

    const char *utf8 = text.UTF8String;
    if (!utf8) return;

    remote_call_with_session(self.springboardSession, ^{
        uint64_t str = ov_nsstring(utf8);
        if (r_is_objc_ptr(str)) {
            r_msg2_main(self.bodyLabel, "setText:", str, 0, 0, 0);
        }
    });
}

- (void)removeOverlayLocked
{
    if (!self.springboardSession) {
        self.window = 0;
        self.titleLabel = 0;
        self.bodyLabel = 0;
        self.runSwitch = 0;
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
    self.runSwitch = 0;
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
        [self setStatusLineLocked:@"内核未就绪"];
        return;
    }

    // 同上：self proc 没解析出来时整张进程表都走不动，先等下一拍。
    if (!proc_self()) {
        kutils_reset_self_cache();
        [self setStatusLineLocked:@"内核会话建立中…"];
        return;
    }

    if (![self lookupTargetLocked]) {
        self.lastListText = nil;
        [self setStatusLineLocked:[NSString stringWithFormat:@"没有找到进程 %@（未运行？）",
                                   self.processName ?: @"?"]];
        return;
    }

    RemoteCallSession *session = ov_attach(self.processName, self.procAddr,
                                           kOverlayAttachTimeoutMS, NO);
    if (!session) {
        [self setStatusLineLocked:@"目标当前不在前台（已挂起），等待中…"];
        return;
    }

    NSMutableString *text = [NSMutableString string];
    NSMutableArray<NSString *> *mainLines = [NSMutableArray array];
    NSMutableArray<NSString *> *thirdLines = [NSMutableArray array];
    NSMutableArray<NSString *> *systemLines = [NSMutableArray array];

    __block NSUInteger total = 0;
    __block NSUInteger thirdCount = 0;
    __block NSUInteger systemCount = 0;
    __block BOOL truncated = NO;

    remote_call_with_session(session, ^{
        uint64_t count = r_dlsym_call(kOverlayDylibCallTimeout, "_dyld_image_count",
                                      0, 0, 0, 0, 0, 0, 0, 0);
        if (count == 0 || count > 4096) return;

        CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + kOverlayDylibDeadline;

        for (uint64_t i = 0; i < count; i++) {
            if (CFAbsoluteTimeGetCurrent() > deadline) {
                truncated = YES;
                break;
            }

            uint64_t base = r_dlsym_call(kOverlayDylibCallTimeout, "_dyld_get_image_header",
                                         i, 0, 0, 0, 0, 0, 0, 0);
            uint64_t namePtr = r_dlsym_call(kOverlayDylibCallTimeout, "_dyld_get_image_name",
                                            i, 0, 0, 0, 0, 0, 0, 0);

            char buffer[512] = {0};
            if (namePtr != 0) {
                remote_read(namePtr, buffer, sizeof(buffer) - 1);
            }

            NSString *path = [NSString stringWithUTF8String:buffer];
            if (path.length == 0) path = @"";

            total += 1;

            if (i == 0) {
                [mainLines addObject:[NSString stringWithFormat:@"  0x%llx %@",
                                      (unsigned long long)base, ov_short_name(path, 26)]];
            } else if (ov_path_is_third_party(path)) {
                thirdCount += 1;
                if (thirdLines.count < kOverlayMaxThirdParty) {
                    [thirdLines addObject:[NSString stringWithFormat:@"  0x%llx %@",
                                           (unsigned long long)base, ov_short_name(path, 24)]];
                }
            } else {
                systemCount += 1;
                if (systemLines.count < kOverlayMaxSystem) {
                    [systemLines addObject:[NSString stringWithFormat:@"  0x%llx %@",
                                            (unsigned long long)base, ov_short_name(path, 24)]];
                }
            }
        }
    });

    if (total == 0) {
        [self setStatusLineLocked:@"读取失败（dyld 返回 0）"];
        return;
    }

    [text appendFormat:@"共 %lu 项 · 第三方 %lu · 系统 %lu%@\n",
     (unsigned long)total, (unsigned long)thirdCount, (unsigned long)systemCount,
     truncated ? @"（超时）" : @""];

    if (mainLines.count > 0) {
        [text appendString:@"主程序\n"];
        for (NSString *line in mainLines) [text appendFormat:@"%@\n", line];
    }
    if (thirdLines.count > 0) {
        [text appendString:@"第三方库\n"];
        for (NSString *line in thirdLines) [text appendFormat:@"%@\n", line];
        if (thirdCount > thirdLines.count) {
            [text appendFormat:@"  … 共 %lu 个\n", (unsigned long)thirdCount];
        }
    }
    if (systemLines.count > 0) {
        [text appendString:@"系统库\n"];
        for (NSString *line in systemLines) [text appendFormat:@"%@\n", line];
        if (systemCount > systemLines.count) {
            [text appendFormat:@"  … 共 %lu 个\n", (unsigned long)systemCount];
        }
    }

    self.lastListText = text;

    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"HH:mm:ss";
    [self setStatusLineLocked:[NSString stringWithFormat:@"已更新 %@",
                               [formatter stringFromDate:[NSDate date]]]];
}

@end
