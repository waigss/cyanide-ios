//
//  LibraryOverlayController.m
//  Cyanide
//
//  在 SpringBoard 里挂一个悬浮窗显示指定进程的库与基址。
//
//  工作流程：
//    1. startForProcessName:pid:procAddr:  打开静音保活、注册前台变化通知、起 2s 轮询
//    2. 每轮先确保 SpringBoard 会话与悬浮窗存在，然后尝试附着目标进程
//    3. 目标在前台（有可劫持线程）时附着成功 → 读 dyld 列表 → 写回悬浮窗文本
//    4. 目标被系统挂起时附着失败 → 悬浮窗显示「等待目标进入前台」
//
//  所有远程调用都串行跑在一条专用队列上：两个 RemoteCallSession（SpringBoard /
//  目标进程）通过 remote_call_with_session() 分时压栈，避免互相污染状态。
//

#import "LibraryOverlayController.h"

#import "../TaskRop/RemoteCall.h"
#import "../tweaks/remote_objc.h"
#import "../kexploit/kexploit_opa334.h"
#import "../DSKeepAlive.h"

#import <UIKit/UIKit.h>
#import <notify.h>

static const char *kOverlayAssocKey = "cyanideLibraryOverlayWindow";
static const int kOverlayLabelTag = 0x43A1;

static const NSTimeInterval kOverlayRetryInterval = 2.0;
static const NSTimeInterval kOverlayDylibDeadline = 15.0;
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
// 超时故意设短（4s）：悬浮窗要周期性试探，不能让每次失败阻塞太久。
static RemoteCallSession *ov_attach(NSString *name, uint64_t procAddr)
{
    for (int attempt = 0; attempt < 2; attempt++) {
        if (procAddr != 0) g_RC_targetProcOverride = procAddr;

        RemoteCallSession *session =
            [[RemoteCallSession alloc] initWithProcess:name
                                    useMigFilterBypass:(attempt == 1)
                               firstExceptionTimeoutMS:4000];

        if (session) return session;

        g_RC_targetProcOverride = 0;

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

@property (nonatomic, assign) BOOL active;
@property (nonatomic, assign) BOOL busy;
@property (nonatomic, assign) BOOL needRefresh;

@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, strong) RemoteCallSession *springboardSession;
@property (nonatomic, assign) uint64_t window;
@property (nonatomic, assign) uint64_t label;

@property (nonatomic, assign) int frontmostToken;
@property (nonatomic, strong) dispatch_source_t retryTimer;

// 屏幕尺寸在 start（主线程）时取好，避免在队列线程上碰 UIKit。
@property (nonatomic, assign) CGSize screenSize;
@property (nonatomic, copy) NSString *lastText;

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
    }
    return self;
}

- (BOOL)isActive
{
    return self.active;
}

- (NSString *)activeProcessName
{
    return self.active ? self.processName : nil;
}

#pragma mark - 生命周期

- (void)startForProcessName:(NSString *)processName pid:(int)pid procAddr:(uint64_t)procAddr
{
    if (processName.length == 0) return;

    [self stop];

    self.processName = processName;
    self.pid = pid;
    self.procAddr = procAddr;
    self.active = YES;
    self.needRefresh = YES;
    self.busy = NO;
    self.lastText = nil;
    self.screenSize = [UIScreen mainScreen].bounds.size;

    // 切到目标 App 后本进程要活着才能继续探测，靠静音音频保活。
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
            self.needRefresh = YES;
        });
        self.frontmostToken = token;
    }

    if (!self.retryTimer) {
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.queue);
        if (timer) {
            dispatch_source_set_timer(timer,
                                      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(NSEC_PER_SEC)),
                                      (uint64_t)(kOverlayRetryInterval * NSEC_PER_SEC),
                                      (uint64_t)(0.5 * NSEC_PER_SEC));
            dispatch_source_set_event_handler(timer, ^{
                __strong typeof(weakSelf) self = weakSelf;
                if (!self) return;
                [self tick];
            });
            dispatch_resume(timer);
            self.retryTimer = timer;
        }
    }

    dispatch_async(self.queue, ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        [self tick];
    });
}

- (void)stop
{
    if (!self.active && !self.retryTimer) return;

    self.active = NO;
    self.needRefresh = NO;

    if (self.retryTimer) {
        dispatch_source_cancel(self.retryTimer);
        self.retryTimer = nil;
    }

    if (self.frontmostToken >= 0) {
        notify_cancel(self.frontmostToken);
        self.frontmostToken = -1;
    }

    dispatch_sync(self.queue, ^{
        [self removeOverlayLocked];
    });

    self.springboardSession = nil;
    self.processName = nil;
}

#pragma mark - 轮询

- (void)tick
{
    if (!self.active || self.busy || !self.needRefresh) return;

    self.busy = YES;
    @try {
        if (!self.springboardSession && ![self installOverlayLocked]) {
            return;
        }

        NSString *text = [self libraryTextLocked];
        if (text.length > 0) {
            [self updateOverlayTextLocked:text];
            self.needRefresh = NO;
        } else {
            [self updateOverlayTextLocked:
                [NSString stringWithFormat:
                 @"%@ (PID %d)\n等待目标进入前台…\n（切到该 App 后会自动读取）",
                 self.processName, self.pid]];
        }
    } @finally {
        self.busy = NO;
    }
}

#pragma mark - 悬浮窗

- (BOOL)installOverlayLocked
{
    if (!kexploit_krw_ready()) return NO;

    RemoteCallSession *session =
        [[RemoteCallSession alloc] initWithProcess:@"SpringBoard"
                               useMigFilterBypass:NO
                          firstExceptionTimeoutMS:12000];
    if (!session) return NO;

    self.springboardSession = session;

    __block BOOL ok = NO;
    __block uint64_t builtWindow = 0;
    __block uint64_t builtLabel = 0;

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

        CGRect screen = CGRectMake(0, 0, MAX(200.0, self.screenSize.width), MAX(320.0, self.screenSize.height));
        CGFloat width = MAX(200.0, screen.size.width - 16.0);
        CGFloat height = MIN(screen.size.height * 0.45, 420.0);
        CGRect windowRect = CGRectMake(8.0, 60.0, width, height);

        ov_set_rect(window, "setFrame:", windowRect);
        ov_set_double(window, "setWindowLevel:", 999999.0);
        r_msg2_main(window, "setUserInteractionEnabled:", 0, 0, 0, 0);

        uint64_t background = ov_color(0.0, 0.82);
        if (r_is_objc_ptr(background)) {
            r_msg2_main(window, "setBackgroundColor:", background, 0, 0, 0);
        }

        uint64_t UILabelClass = r_class("UILabel");
        uint64_t labelAllocated = r_is_objc_ptr(UILabelClass)
            ? r_msg2_main(UILabelClass, "alloc", 0, 0, 0, 0) : 0;
        uint64_t label = r_is_objc_ptr(labelAllocated)
            ? r_msg2_main(labelAllocated, "init", 0, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(label)) return;

        r_msg2_main(label, "setNumberOfLines:", 0, 0, 0, 0);
        r_msg2_main(label, "setTag:", kOverlayLabelTag, 0, 0, 0);
        r_msg2_main(label, "setTextAlignment:", 0, 0, 0, 0);

        double fontSize = 9.0;
        double fontWeight = 0.0;
        uint64_t UIFontClass = r_class("UIFont");
        uint64_t font = r_is_objc_ptr(UIFontClass)
            ? r_msg2_main_raw(UIFontClass, "monospacedSystemFontOfSize:weight:",
                              &fontSize, sizeof(fontSize),
                              &fontWeight, sizeof(fontWeight),
                              NULL, 0, NULL, 0) : 0;
        if (r_is_objc_ptr(font)) {
            r_msg2_main(label, "setFont:", font, 0, 0, 0);
        }

        uint64_t whiteColor = r_is_objc_ptr(r_class("UIColor"))
            ? r_msg2_main(r_class("UIColor"), "whiteColor", 0, 0, 0, 0) : 0;
        if (r_is_objc_ptr(whiteColor)) {
            r_msg2_main(label, "setTextColor:", whiteColor, 0, 0, 0);
        }

        CGRect labelRect = CGRectMake(8.0, 8.0,
                                      MAX(1.0, windowRect.size.width - 16.0),
                                      MAX(1.0, windowRect.size.height - 16.0));
        ov_set_rect(label, "setFrame:", labelRect);

        r_msg2_main(window, "addSubview:", label, 0, 0, 0);
        r_msg2_main(window, "setHidden:", 0, 0, 0, 0);

        // 把 window 挂到 SpringBoard 的 UIApplication 上，避免被释放。
        uint64_t key = r_sel(kOverlayAssocKey);
        if (key) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject",
                         app, key, window, 1, 0, 0, 0, 0);
        }

        builtWindow = window;
        builtLabel = label;
        ok = YES;
    });

    self.window = builtWindow;
    self.label = builtLabel;

    if (!ok) {
        self.springboardSession = nil;
    }
    return ok;
}

- (void)updateOverlayTextLocked:(NSString *)text
{
    if (!self.springboardSession || !r_is_objc_ptr(self.label)) return;
    if (text.length == 0 || [text isEqualToString:self.lastText]) return;

    const char *utf8 = text.UTF8String;
    if (!utf8) return;

    self.lastText = text;

    remote_call_with_session(self.springboardSession, ^{
        uint64_t str = ov_nsstring(utf8);
        if (r_is_objc_ptr(str)) {
            r_msg2_main(self.label, "setText:", str, 0, 0, 0);
        }
    });
}

- (void)removeOverlayLocked
{
    if (!self.springboardSession) {
        self.window = 0;
        self.label = 0;
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
    self.label = 0;
}

#pragma mark - 读库

// 返回 nil 表示这次没读到（目标大概被挂起了）。
- (NSString *)libraryTextLocked
{
    if (!kexploit_krw_ready()) return nil;

    RemoteCallSession *session = ov_attach(self.processName, self.procAddr);
    if (!session) return nil;

    NSMutableString *text = [NSMutableString string];
    [text appendFormat:@"%@ (PID %d)\n", self.processName, self.pid];

    __block NSUInteger total = 0;
    __block NSUInteger thirdCount = 0;
    __block NSUInteger systemCount = 0;
    __block BOOL truncated = NO;

    NSMutableArray<NSString *> *mainLines = [NSMutableArray array];
    NSMutableArray<NSString *> *thirdLines = [NSMutableArray array];
    NSMutableArray<NSString *> *systemLines = [NSMutableArray array];

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
                                      (unsigned long long)base,
                                      ov_short_name(path, 26)]];
            } else if (ov_path_is_third_party(path)) {
                thirdCount += 1;
                if (thirdLines.count < kOverlayMaxThirdParty) {
                    [thirdLines addObject:[NSString stringWithFormat:@"  0x%llx %@",
                                           (unsigned long long)base,
                                           ov_short_name(path, 24)]];
                }
            } else {
                systemCount += 1;
                if (systemLines.count < kOverlayMaxSystem) {
                    [systemLines addObject:[NSString stringWithFormat:@"  0x%llx %@",
                                            (unsigned long long)base,
                                            ov_short_name(path, 24)]];
                }
            }
        }
    });

    if (total == 0) return nil;

    [text appendFormat:@"共 %lu 项 · 第三方 %lu · 系统 %lu%@\n",
     (unsigned long)total, (unsigned long)thirdCount, (unsigned long)systemCount,
     truncated ? @"（超时，不完整）" : @""];

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

    return text;
}

@end
