//
//  CyanideImGuiOverlay.m
//  Cyanide
//
//  SpringBoard 全局悬浮窗 + 全屏透明画布，界面是 ImGui 的样子。
//
//  为什么是「本地渲染 + 远程贴图」而不是在 SpringBoard 里建视图树：
//    远程建一个控件要十几条 ROP 消息（每条带 settle 等待），一条分隔线都要
//    花钱；而把整帧画成一张 PNG 再推过去，帧成本和图元数量无关 ——
//    malloc + remote_write（共享页 memcpy）+ 2 条消息。
//
//  输入怎么回来：
//    远程进程里跑不了我们的代码，所以点不了 UIButton。这里用一组「隐形控件」
//    —— UISwitch / UISlider / UISegmentedControl + alpha 0.02（UIKit 的
//    hitTest 只忽略 alpha < 0.01，所以 0.02 仍然可点、但基本看不见），
//    按 ImGui 的绘制位置摆好，本进程每 160ms 读一次 isOn / value /
//    selectedSegmentIndex，读到变化就重画。
//
//  点击穿透：
//    canvasWindow 的 userInteractionEnabled = NO，画布以下全是游戏本身；
//    panelWindow 只有面板那么大，面板以外的触摸不会被它接住。
//

#import "CyanideImGuiOverlay.h"

#import "../imgui/IGUI.h"
#import "../imgui/IGDrawList.h"
#import "../TaskRop/RemoteCall.h"
#import "../tweaks/remote_objc.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/kutils.h"
#import "../DSKeepAlive.h"
#import "../SettingsViewController.h"
#import "CyanideLog.h"

#import <UIKit/UIKit.h>
#import <math.h>
#import <string.h>

#pragma mark - 常量

static const char *kIGKeyCanvas = "cyanideImGuiCanvasWindow";
static const char *kIGKeyPanel  = "cyanideImGuiPanelWindow";
static const char *kIGKeyBubble = "cyanideImGuiBubbleWindow";

static const CGFloat kIGPanelWidth   = 252.0;
static const CGFloat kIGPanelMargin  = 10.0;
static const CGFloat kIGPanelTop     = 64.0;
static const CGFloat kIGBubbleSize   = 38.0;
static const CGFloat kIGCanvasLevel  = 1000000.0;
static const CGFloat kIGPanelLevel   = 1000001.0;
static const CGFloat kIGRenderScale  = 2.0;

static const NSTimeInterval kIGTickInterval    = 0.16;
static const NSTimeInterval kIGMinPushInterval = 0.15;

// 远程消息之间的等待。默认 50ms 是给「一条一条点」的场景留的余量；
// 这里要连续推帧、轮询，降到 8ms。调大更稳，调小更快。
static const uint32_t kIGSettleMicroseconds = 8000;

static const uint32_t kIGRemoteBufferBytes = 4u * 1024u * 1024u;

// 不透明度只有 5 档（UISegmentedControl 的 selectedSegmentIndex 是整数，
// 能一条 objc_msgSend 读回来；UISlider 的 value 是 float，读不回来）。
static const CGFloat kIGAlphaSteps[5] = {40.0, 95.0, 150.0, 205.0, 255.0};
static const int kIGMaxPushFailures = 4;

#pragma mark - 画布图元

@interface IGCanvasItem : NSObject
@property (nonatomic) IGDrawCmdType type;
@property (nonatomic) IGVec2 a;
@property (nonatomic) IGVec2 b;
@property (nonatomic) CGFloat radius;
@property (nonatomic) CGFloat thickness;
@property (nonatomic) CGFloat fontSize;
@property (nonatomic) uint32_t color;
@property (nonatomic, copy) NSString *text;
@end

@implementation IGCanvasItem
@end

#pragma mark - 远程小工具

static NSMutableDictionary<NSString *, NSNumber *> *gIGClassCache = nil;
static NSMutableDictionary<NSString *, NSNumber *> *gIGSelectorCache = nil;
static NSRecursiveLock *gIGRemoteCacheLock = nil;

static void ig_remote_cache_init(void)
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gIGClassCache = [NSMutableDictionary dictionaryWithCapacity:24];
        gIGSelectorCache = [NSMutableDictionary dictionaryWithCapacity:64];
        gIGRemoteCacheLock = [[NSRecursiveLock alloc] init];
    });
}

static void ig_remote_cache_reset(void)
{
    ig_remote_cache_init();
    [gIGRemoteCacheLock lock];
    [gIGClassCache removeAllObjects];
    [gIGSelectorCache removeAllObjects];
    [gIGRemoteCacheLock unlock];
}

static uint64_t ig_class(NSString *name)
{
    ig_remote_cache_init();
    [gIGRemoteCacheLock lock];
    NSNumber *cached = gIGClassCache[name];
    [gIGRemoteCacheLock unlock];
    if (cached) return cached.unsignedLongLongValue;

    uint64_t value = r_class(name.UTF8String);
    if (value) {
        [gIGRemoteCacheLock lock];
        gIGClassCache[name] = @(value);
        [gIGRemoteCacheLock unlock];
    }
    return value;
}

static uint64_t ig_sel(NSString *name)
{
    ig_remote_cache_init();
    [gIGRemoteCacheLock lock];
    NSNumber *cached = gIGSelectorCache[name];
    [gIGRemoteCacheLock unlock];
    if (cached) return cached.unsignedLongLongValue;

    uint64_t value = r_sel(name.UTF8String);
    if (value) {
        [gIGRemoteCacheLock lock];
        gIGSelectorCache[name] = @(value);
        [gIGRemoteCacheLock unlock];
    }
    return value;
}

// 无参 getter：直接一条 objc_msgSend ROP，不建 NSInvocation。
// 只读标量属性，不会改 UIKit 的对象图，所以可以脱离主线程调用。
static uint64_t ig_get(uint64_t object, NSString *selName)
{
    if (!r_is_objc_ptr(object)) return 0;
    uint64_t sel = ig_sel(selName);
    if (!sel) return 0;
    return r_msg(object, sel, 0, 0, 0, 0);
}

static void ig_main_rect(uint64_t object, const char *sel, CGRect rect)
{
    if (!r_is_objc_ptr(object) || !sel) return;
    r_msg2_main_raw(object, sel, &rect, sizeof(rect), NULL, 0, NULL, 0, NULL, 0);
}

static void ig_main_double(uint64_t object, const char *sel, double value)
{
    if (!r_is_objc_ptr(object) || !sel) return;
    r_msg2_main_raw(object, sel, &value, sizeof(value), NULL, 0, NULL, 0, NULL, 0);
}

static void ig_main_call(uint64_t object, const char *sel, uint64_t a0)
{
    if (!r_is_objc_ptr(object) || !sel) return;
    r_msg2_main(object, sel, a0, 0, 0, 0);
}

static void ig_main_call0(uint64_t object, const char *sel)
{
    if (!r_is_objc_ptr(object) || !sel) return;
    r_msg2_main(object, sel, 0, 0, 0, 0);
}

static uint64_t ig_nsstring(NSString *text)
{
    if (text.length == 0) return 0;
    const char *utf8 = text.UTF8String;
    if (!utf8) return 0;
    return r_nsstr_retained(utf8);
}

static void ig_release(uint64_t object)
{
    if (!r_is_objc_ptr(object)) return;
    uint64_t sel = ig_sel(@"release");
    if (!sel) return;
    r_msg(object, sel, 0, 0, 0, 0);
}

static uint32_t ig_color_argb(UIColor *color)
{
    CGFloat r = 1.0, g = 1.0, b = 1.0, a = 1.0;
    if (![color getRed:&r green:&g blue:&b alpha:&a]) {
        CGFloat white = 1.0;
        CGFloat alpha = 1.0;
        if ([color getWhite:&white alpha:&alpha]) {
            r = g = b = white;
            a = alpha;
        }
    }
    return IGColorMake(r, g, b, a);
}

#pragma mark - 远程视图工厂

static uint64_t ig_window_create(uint64_t scene, CGRect frame)
{
    uint64_t cls = ig_class(@"UIWindow");
    if (!r_is_objc_ptr(cls)) return 0;

    uint64_t alloc = r_msg2_main(cls, "alloc", 0, 0, 0, 0);
    if (!r_is_objc_ptr(alloc)) return 0;

    uint64_t window = 0;
    if (r_is_objc_ptr(scene)) {
        window = r_msg2_main(alloc, "initWithWindowScene:", scene, 0, 0, 0);
    }
    if (!r_is_objc_ptr(window)) {
        alloc = r_msg2_main(cls, "alloc", 0, 0, 0, 0);
        if (!r_is_objc_ptr(alloc)) return 0;
        window = r_msg2_main_raw(alloc, "initWithFrame:", &frame, sizeof(frame),
                                 NULL, 0, NULL, 0, NULL, 0);
    } else if (!CGRectEqualToRect(frame, CGRectZero)) {
        ig_main_rect(window, "setFrame:", frame);
    }
    return window;
}

// 隐形开关：alpha 0.02 让 UIKit 仍然做 hitTest，但肉眼基本看不到。
static uint64_t ig_make_switch(uint64_t parent, CGRect frame, BOOL on)
{
    uint64_t cls = ig_class(@"UISwitch");
    if (!r_is_objc_ptr(cls)) return 0;

    uint64_t alloc = r_msg2_main(cls, "alloc", 0, 0, 0, 0);
    uint64_t control = r_is_objc_ptr(alloc) ? r_msg2_main(alloc, "init", 0, 0, 0, 0) : 0;
    if (!r_is_objc_ptr(control)) return 0;

    ig_main_rect(control, "setFrame:", frame);
    ig_main_double(control, "setAlpha:", 0.02);
    ig_main_call(control, "setOn:", on ? 1 : 0);

    uint64_t clear = r_msg2_main(ig_class(@"UIColor"), "clearColor", 0, 0, 0, 0);
    if (r_is_objc_ptr(clear)) {
        ig_main_call(control, "setOnTintColor:", clear);
        ig_main_call(control, "setThumbTintColor:", clear);
    }

    ig_main_call(parent, "addSubview:", control);
    return control;
}

static uint64_t ig_make_segments(uint64_t parent, CGRect frame, NSArray<NSString *> *labels, NSInteger active)
{
    uint64_t cls = ig_class(@"UISegmentedControl");
    if (!r_is_objc_ptr(cls)) return 0;

    uint64_t alloc = r_msg2_main(cls, "alloc", 0, 0, 0, 0);
    if (!r_is_objc_ptr(alloc)) return 0;

    uint64_t control = r_msg2_main_raw(alloc, "initWithFrame:", &frame, sizeof(frame),
                                       NULL, 0, NULL, 0, NULL, 0);
    if (!r_is_objc_ptr(control)) return 0;

    ig_main_double(control, "setAlpha:", 0.02);
    for (NSString *label in labels) {
        uint64_t text = ig_nsstring(label);
        if (!r_is_objc_ptr(text)) continue;
        r_msg2_main(control, "insertSegmentWithTitle:animated:", text, 0, 0, 0);
        ig_release(text);
    }
    ig_main_call(control, "setSelectedSegmentIndex:", (uint64_t)MAX((NSInteger)0, active));

    ig_main_call(parent, "addSubview:", control);
    return control;
}

#pragma mark - 控制器

typedef NS_ENUM(NSInteger, IGOverlayState) {
    IGOverlayStateIdle = 0,
    IGOverlayStateStarting,
    IGOverlayStateRunning,
    IGOverlayStateFailed,
};

@interface CyanideImGuiOverlay ()
- (void)tick;
@end

@implementation CyanideImGuiOverlay {
    IGOverlayState _state;
    dispatch_queue_t _queue;
    dispatch_source_t _timer;
    RemoteCallSession *_session;

    CGSize _screenSize;
    CGRect _panelRect;
    CGRect _bubbleRect;
    CGFloat _renderScale;

    uint64_t _canvasWindow;
    uint64_t _panelWindow;
    uint64_t _bubbleWindow;
    uint64_t _imageView;
    uint64_t _fallbackLabel;

    uint64_t _switchDemo;
    uint64_t _switchGrid;
    uint64_t _switchHide;
    uint64_t _switchRestore;
    uint64_t _segWidth;
    uint64_t _segAlpha;
    uint64_t _segAnchor;

    uint64_t _remoteBuffer;
    uint32_t _remoteBufferCapacity;

    BOOL _panelHidden;
    BOOL _imagePushVerified;
    int _pushFailures;
    NSTimeInterval _lastPushAt;
    double _lastPushMS;
    double _lastRenderMS;
    double _fps;
    double _demoPhase;
    NSUInteger _lastPrimCount;

    CGFloat _lineWidth;
    CGFloat _canvasAlpha;
    NSInteger _widthIndex;
    NSInteger _alphaIndex;
    NSInteger _anchorIndex;

    BOOL _demoEnabled;
    BOOL _gridEnabled;

    NSMutableArray<IGCanvasItem *> *_primitives;
    NSLock *_primitivesLock;
    IGUI *_ui;

    BOOL _busy;
    BOOL _needsPush;
    NSString *_statusLine;
}

+ (instancetype)sharedOverlay
{
    static CyanideImGuiOverlay *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[CyanideImGuiOverlay alloc] init];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.cyanide.imguioverlay", DISPATCH_QUEUE_SERIAL);
        _primitives = [NSMutableArray array];
        _primitivesLock = [[NSLock alloc] init];
        _ui = [[IGUI alloc] init];
        IGStyle style = _ui.style;
        style.itemSpacingY = 4.0;
        _ui.style = style;
        _renderScale = kIGRenderScale;
        _widthIndex = 1;                       // 线宽 2.0
        _alphaIndex = 3;                       // 不透明度 205
        _lineWidth = (CGFloat)(_widthIndex + 1);
        _canvasAlpha = kIGAlphaSteps[_alphaIndex];
        _anchorIndex = 0;
        _demoEnabled = NO;
        _gridEnabled = NO;
        _state = IGOverlayStateIdle;
        _statusLine = @"未启动";
    }
    return self;
}

- (BOOL)isActive
{
    return _state == IGOverlayStateRunning;
}

- (BOOL)isStarting
{
    return _state == IGOverlayStateStarting;
}

- (NSString *)statusLine
{
    @synchronized (self) {
        return _statusLine ?: @"";
    }
}

- (void)setStatus:(NSString *)line
{
    @synchronized (self) {
        _statusLine = [line copy];
    }
}

#pragma mark - 生命周期

- (void)start
{
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self start]; });
        return;
    }

    @synchronized (self) {
        if (_state == IGOverlayStateStarting || _state == IGOverlayStateRunning) return;
        _state = IGOverlayStateStarting;
    }

    _screenSize = [UIScreen mainScreen].bounds.size;
    CGFloat screenScale = [UIScreen mainScreen].scale;
    _renderScale = MIN(MAX(screenScale, 1.0), kIGRenderScale);

    [self setStatus:@"正在挂载…"];
    cyanide_log(@"[IMGUI] start: screen=%.0fx%.0f scale=%.1f",
                _screenSize.width, _screenSize.height, _renderScale);

    // 切到别的 App 后本进程要被保活，否则轮询和推帧都会停。
    ds_keepalive_apply_enabled(YES);

    dispatch_async(_queue, ^{
        [self installLocked];
    });
}

- (void)stop
{
    dispatch_async(_queue, ^{
        [self teardownLocked];
    });
}

- (void)installLocked
{
    if (!kexploit_krw_ready()) {
        BOOL ready = settings_ensure_kernel_ready();
        if (!ready) {
            [self setStatus:@"内核未就绪"];
            cyanide_log(@"[IMGUI] install aborted: krw not ready");
            @synchronized (self) { _state = IGOverlayStateFailed; }
            return;
        }
    }

    ig_remote_cache_reset();

    RemoteCallSession *session =
        [[RemoteCallSession alloc] initWithProcess:@"SpringBoard"
                               useMigFilterBypass:NO
                          firstExceptionTimeoutMS:12000];
    if (!session) {
        [self setStatus:[NSString stringWithFormat:@"SpringBoard 会话失败 (%d)",
                         (int)remote_call_last_init_failure()]];
        cyanide_log(@"[IMGUI] SpringBoard session failed: %d", (int)remote_call_last_init_failure());
        @synchronized (self) { _state = IGOverlayStateFailed; }
        return;
    }
    _session = session;
    cyanide_log(@"[IMGUI] SpringBoard session ok pid=%d", session.pid);

    [self computeLayoutLocked];

    __block uint64_t canvasWindow = 0;
    __block uint64_t panelWindow = 0;
    __block uint64_t bubbleWindow = 0;
    __block uint64_t imageView = 0;
    __block uint64_t swDemo = 0, swGrid = 0, swHide = 0, swRestore = 0;
    __block uint64_t slWidth = 0, slAlpha = 0, segAnchor = 0;
    __block BOOL built = NO;

    CGRect panelRect = _panelRect;
    CGRect bubbleRect = _bubbleRect;
    CGSize screenSize = _screenSize;
    BOOL demoOn = _demoEnabled;
    BOOL gridOn = _gridEnabled;
    NSInteger widthIndex = _widthIndex;
    NSInteger alphaIndex = _alphaIndex;
    NSInteger anchorIndex = _anchorIndex;

    uint32_t previousSettle = r_settle_us(kIGSettleMicroseconds);

    remote_call_with_session(session, ^{
        uint64_t appClass = ig_class(@"UIApplication");
        uint64_t app = r_is_objc_ptr(appClass)
            ? r_msg2_main(appClass, "sharedApplication", 0, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(app)) {
            cyanide_log(@"[IMGUI] no UIApplication");
            return;
        }

        uint64_t keyWindow = r_msg2_main(app, "keyWindow", 0, 0, 0, 0);
        if (!r_is_objc_ptr(keyWindow)) {
            uint64_t windows = r_msg2_main(app, "windows", 0, 0, 0, 0);
            uint64_t count = r_is_objc_ptr(windows) ? r_msg2_main(windows, "count", 0, 0, 0, 0) : 0;
            if (count > 0 && count < 64) {
                keyWindow = r_msg2_main(windows, "objectAtIndex:", 0, 0, 0, 0);
            }
        }

        uint64_t scene = r_is_objc_ptr(keyWindow)
            ? r_msg2_main(keyWindow, "windowScene", 0, 0, 0, 0) : 0;

        uint64_t clear = r_msg2_main(ig_class(@"UIColor"), "clearColor", 0, 0, 0, 0);

        // ── 画布窗口：全屏、透明、不吃触摸 ──────────────────────────
        CGRect screenRect = CGRectMake(0.0, 0.0, screenSize.width, screenSize.height);
        canvasWindow = ig_window_create(scene, screenRect);
        if (!r_is_objc_ptr(canvasWindow)) {
            cyanide_log(@"[IMGUI] canvas window create failed");
            return;
        }
        ig_main_double(canvasWindow, "setWindowLevel:", kIGCanvasLevel);
        ig_main_call(canvasWindow, "setOpaque:", 0);
        ig_main_call(canvasWindow, "setUserInteractionEnabled:", 0);
        if (r_is_objc_ptr(clear)) ig_main_call(canvasWindow, "setBackgroundColor:", clear);

        uint64_t imageClass = ig_class(@"UIImageView");
        uint64_t imageAlloc = r_msg2_main(imageClass, "alloc", 0, 0, 0, 0);
        imageView = r_is_objc_ptr(imageAlloc)
            ? r_msg2_main_raw(imageAlloc, "initWithFrame:", &screenRect, sizeof(screenRect),
                              NULL, 0, NULL, 0, NULL, 0)
            : 0;
        if (!r_is_objc_ptr(imageView)) {
            cyanide_log(@"[IMGUI] image view create failed");
            return;
        }
        ig_main_call(imageView, "setUserInteractionEnabled:", 0);
        ig_main_call(imageView, "setContentMode:", 1); // scaleAspectFit
        if (r_is_objc_ptr(clear)) ig_main_call(imageView, "setBackgroundColor:", clear);
        ig_main_call(canvasWindow, "addSubview:", imageView);
        ig_main_call(canvasWindow, "setHidden:", 0);

        // ── 面板窗口：只有面板大小，隐形控件都挂这儿 ────────────────
        panelWindow = ig_window_create(scene, panelRect);
        if (!r_is_objc_ptr(panelWindow)) {
            cyanide_log(@"[IMGUI] panel window create failed");
            return;
        }
        ig_main_double(panelWindow, "setWindowLevel:", kIGPanelLevel);
        ig_main_call(panelWindow, "setOpaque:", 0);
        if (r_is_objc_ptr(clear)) ig_main_call(panelWindow, "setBackgroundColor:", clear);
        ig_main_call(panelWindow, "setHidden:", 0);

        // ── 收起后的小圆钮 ─────────────────────────────────────────
        bubbleWindow = ig_window_create(scene, bubbleRect);
        if (r_is_objc_ptr(bubbleWindow)) {
            ig_main_double(bubbleWindow, "setWindowLevel:", kIGPanelLevel);
            ig_main_call(bubbleWindow, "setOpaque:", 0);
            if (r_is_objc_ptr(clear)) ig_main_call(bubbleWindow, "setBackgroundColor:", clear);
            ig_main_call(bubbleWindow, "setHidden:", 1);
        }

        // 控件矩形：拿和渲染完全同一套布局跑一遍，再减去窗口原点。
        __block CGRect rowDemo = CGRectZero;
        __block CGRect rowGrid = CGRectZero;
        __block CGRect rowHide = CGRectZero;
        __block CGRect rowWidth = CGRectZero;
        __block CGRect rowAlpha = CGRectZero;
        __block CGRect rowAnchor = CGRectZero;

        [self captureControlRectsLocked:^(NSString *key, CGRect rect) {
            if ([key isEqualToString:@"demo"]) rowDemo = rect;
            else if ([key isEqualToString:@"grid"]) rowGrid = rect;
            else if ([key isEqualToString:@"hide"]) rowHide = rect;
            else if ([key isEqualToString:@"width"]) rowWidth = rect;
            else if ([key isEqualToString:@"alpha"]) rowAlpha = rect;
            else if ([key isEqualToString:@"anchor"]) rowAnchor = rect;
        }];

        CGFloat offsetX = -panelRect.origin.x;
        CGFloat offsetY = -panelRect.origin.y;

        swDemo = ig_make_switch(panelWindow, CGRectOffset(rowDemo, offsetX, offsetY), demoOn);
        swGrid = ig_make_switch(panelWindow, CGRectOffset(rowGrid, offsetX, offsetY), gridOn);
        swHide = ig_make_switch(panelWindow, CGRectOffset(rowHide, offsetX, offsetY), NO);
        slWidth = ig_make_segments(panelWindow, CGRectOffset(rowWidth, offsetX, offsetY),
                                   @[@"1", @"2", @"3", @"4", @"5", @"6", @"7", @"8"],
                                   widthIndex);
        slAlpha = ig_make_segments(panelWindow, CGRectOffset(rowAlpha, offsetX, offsetY),
                                   @[@"40", @"95", @"150", @"205", @"255"],
                                   alphaIndex);
        segAnchor = ig_make_segments(panelWindow, CGRectOffset(rowAnchor, offsetX, offsetY),
                                     @[@"Top", @"Right", @"Bottom"], anchorIndex);

        if (r_is_objc_ptr(bubbleWindow)) {
            CGRect restoreFrame = CGRectMake(0.0, 0.0, kIGBubbleSize, kIGBubbleSize);
            swRestore = ig_make_switch(bubbleWindow, restoreFrame, NO);
        }

        // 关联到 UIApplication，避免窗口被释放。
        uint64_t keyCanvas = r_sel(kIGKeyCanvas);
        uint64_t keyPanel = r_sel(kIGKeyPanel);
        uint64_t keyBubble = r_sel(kIGKeyBubble);
        if (keyCanvas) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, keyCanvas, canvasWindow, 1, 0, 0, 0, 0);
        }
        if (keyPanel) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, keyPanel, panelWindow, 1, 0, 0, 0, 0);
        }
        if (keyBubble && r_is_objc_ptr(bubbleWindow)) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, keyBubble, bubbleWindow, 1, 0, 0, 0, 0);
        }

        built = r_is_objc_ptr(canvasWindow) && r_is_objc_ptr(imageView);
        cyanide_log(@"[IMGUI] windows: canvas=0x%llx panel=0x%llx bubble=0x%llx image=0x%llx",
                    canvasWindow, panelWindow, bubbleWindow, imageView);
    });

    r_settle_us(previousSettle);

    _canvasWindow = canvasWindow;
    _panelWindow = panelWindow;
    _bubbleWindow = bubbleWindow;
    _imageView = imageView;
    _switchDemo = swDemo;
    _switchGrid = swGrid;
    _switchHide = swHide;
    _switchRestore = swRestore;
    _segWidth = slWidth;
    _segAlpha = slAlpha;
    _segAnchor = segAnchor;

    if (!built || !r_is_objc_ptr(_imageView)) {
        [self setStatus:@"悬浮窗创建失败"];
        cyanide_log(@"[IMGUI] install failed: windows not built");
        [self teardownLocked];
        @synchronized (self) { _state = IGOverlayStateFailed; }
        return;
    }

    [self ensureRemoteBufferLocked];

    // 第一帧顺带验证「推图」这条路通不通。
    NSData *firstFrame = [self renderFrameLocked];
    if (firstFrame.length > 0) {
        [self pushPNGLocked:firstFrame];
    }

    if (!_imagePushVerified) {
        cyanide_log(@"[IMGUI] image push not verified, installing fallback label");
        [self installFallbackLabelLocked];
    }

    [self startTimerLocked];
    [self setStatus:[NSString stringWithFormat:@"运行中 · %.0f×%.0f · 画布可穿透",
                     _screenSize.width, _screenSize.height]];
    @synchronized (self) { _state = IGOverlayStateRunning; }
    _needsPush = YES;
    cyanide_log(@"[IMGUI] running");
}

- (void)teardownLocked
{
    if (_timer) {
        dispatch_source_cancel(_timer);
        _timer = nil;
    }

    uint64_t canvasWindow = _canvasWindow;
    uint64_t panelWindow = _panelWindow;
    uint64_t bubbleWindow = _bubbleWindow;
    RemoteCallSession *session = _session;

    if (session) {
        NSArray<NSNumber *> *handles = @[@(canvasWindow), @(panelWindow), @(bubbleWindow)];
        uint32_t previousSettle = r_settle_us(kIGSettleMicroseconds);
        remote_call_with_session(session, ^{
            for (NSNumber *number in handles) {
                uint64_t handle = number.unsignedLongLongValue;
                if (!r_is_objc_ptr(handle)) continue;
                ig_main_call(handle, "setHidden:", 1);
                ig_main_call0(handle, "removeFromSuperview");
            }

            uint64_t app = r_msg2_main(ig_class(@"UIApplication"), "sharedApplication", 0, 0, 0, 0);
            if (r_is_objc_ptr(app)) {
                uint64_t keyCanvas = r_sel(kIGKeyCanvas);
                uint64_t keyPanel = r_sel(kIGKeyPanel);
                uint64_t keyBubble = r_sel(kIGKeyBubble);
                if (keyCanvas) {
                    r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, keyCanvas, 0, 1, 0, 0, 0, 0);
                }
                if (keyPanel) {
                    r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, keyPanel, 0, 1, 0, 0, 0, 0);
                }
                if (keyBubble) {
                    r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, keyBubble, 0, 1, 0, 0, 0, 0);
                }
            }
        });
        r_settle_us(previousSettle);
    }

    _canvasWindow = 0;
    _panelWindow = 0;
    _bubbleWindow = 0;
    _imageView = 0;
    _fallbackLabel = 0;
    _switchDemo = 0;
    _switchGrid = 0;
    _switchHide = 0;
    _switchRestore = 0;
    _segWidth = 0;
    _segAlpha = 0;
    _segAnchor = 0;
    _remoteBuffer = 0;
    _remoteBufferCapacity = 0;
    _imagePushVerified = NO;
    _pushFailures = 0;
    _panelHidden = NO;
    _session = nil;

    @synchronized (self) { _state = IGOverlayStateIdle; }
    [self setStatus:@"已停止"];
    cyanide_log(@"[IMGUI] stopped");
}

- (void)startTimerLocked
{
    if (_timer) return;

    __weak typeof(self) weakSelf = self;
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    if (!timer) return;

    dispatch_source_set_timer(timer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kIGTickInterval * NSEC_PER_SEC)),
                              (uint64_t)(kIGTickInterval * NSEC_PER_SEC),
                              (uint64_t)(0.02 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(timer, ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        [self tick];
    });
    dispatch_resume(timer);
    _timer = timer;
}

#pragma mark - 布局

- (void)computeLayoutLocked
{
    CGFloat contentHeight = [_ui measureWithWidth:kIGPanelWidth build:^{
        [self buildPanelRowsWithCapture:nil];
    }];

    CGFloat panelHeight = _ui.style.titleHeight + _ui.style.windowPaddingY * 2.0 + contentHeight;
    CGFloat screenW = _screenSize.width;
    CGFloat screenH = _screenSize.height;

    CGFloat originX = (_anchorIndex == 1) ? (screenW - kIGPanelWidth - kIGPanelMargin) : kIGPanelMargin;
    CGFloat originY = kIGPanelTop;
    if (_anchorIndex == 2) {
        originY = MAX(kIGPanelTop, screenH - panelHeight - 110.0);
    }

    _panelRect = CGRectMake(originX, originY, kIGPanelWidth, panelHeight);
    _bubbleRect = CGRectMake(originX, originY, kIGBubbleSize, kIGBubbleSize);
}

// 用真实原点跑一遍布局，把每个可交互行的屏幕矩形抓出来。
- (void)captureControlRectsLocked:(void (^)(NSString *key, CGRect rect))capture
{
    if (!capture) return;
    [_ui beginFrameWithDisplaySize:_screenSize];
    [_ui beginWindow:@"Cyanide" frame:_panelRect];
    [self buildPanelRowsWithCapture:capture];
    [_ui endWindow];
    [_ui endFrame];
}

- (void)buildPanelRowsWithCapture:(void (^)(NSString *key, CGRect rect))capture
{
    IGUI *ui = _ui;

    [ui text:[NSString stringWithFormat:@"fps %.1f   prims %lu",
              _fps, (unsigned long)_lastPrimCount]];
    [ui textDisabled:[NSString stringWithFormat:@"frame %.0fms   settle %ums",
                      _lastPushMS, (unsigned)kIGSettleMicroseconds / 1000u]];
    [ui separator];

    [ui checkbox:@"Demo lines" value:_demoEnabled];
    if (capture) capture(@"demo", ui.lastItemRect);

    [ui checkbox:@"Grid + crosshair" value:_gridEnabled];
    if (capture) capture(@"grid", ui.lastItemRect);

    [ui separator];

    [ui sliderIntTicks:@"Line width"
                 value:_widthIndex
                   min:0
                   max:7
             valueText:[NSString stringWithFormat:@"%ld", (long)(_widthIndex + 1)]];
    if (capture) capture(@"width", ui.lastItemRect);

    [ui sliderIntTicks:@"Opacity"
                 value:_alphaIndex
                   min:0
                   max:4
             valueText:[NSString stringWithFormat:@"%.0f", _canvasAlpha]];
    if (capture) capture(@"alpha", ui.lastItemRect);

    [ui separator];

    [ui tabBar:@[@"Top", @"Right", @"Bottom"] active:_anchorIndex];
    if (capture) capture(@"anchor", ui.lastItemRect);

    [ui separator];

    [ui button:@"Hide panel"];
    if (capture) capture(@"hide", ui.lastItemRect);

    [ui textDisabled:@"canvas: click-through"];
}

#pragma mark - 轮询

- (void)tick
{
    if (_state != IGOverlayStateRunning) return;
    if (_busy) return;

    _busy = YES;
    @try {
        [self pollLocked];

        NSTimeInterval now = CACurrentMediaTime();
        if (_demoEnabled) _needsPush = YES;

        if (_needsPush && (now - _lastPushAt) >= kIGMinPushInterval) {
            _needsPush = NO;
            [self renderAndPushLocked];
        }
    } @finally {
        _busy = NO;
    }
}

- (void)pollLocked
{
    RemoteCallSession *session = _session;
    if (!session) return;

    if (_panelHidden) {
        uint64_t restoreSwitch = _switchRestore;
        __block BOOL restore = NO;
        remote_call_with_session(session, ^{
            if (r_is_objc_ptr(restoreSwitch)) {
                restore = (ig_get(restoreSwitch, @"isOn") & 0xFF) != 0;
            }
        });
        if (restore) [self showPanelLocked];
        return;
    }

    uint64_t demoSwitch = _switchDemo;
    uint64_t gridSwitch = _switchGrid;
    uint64_t hideSwitch = _switchHide;
    uint64_t widthSegments = _segWidth;
    uint64_t alphaSegments = _segAlpha;
    uint64_t anchorSegments = _segAnchor;

    __block BOOL demo = NO;
    __block BOOL grid = NO;
    __block BOOL hide = NO;
    __block NSInteger widthIndex = _widthIndex;
    __block NSInteger alphaIndex = _alphaIndex;
    __block NSInteger anchor = _anchorIndex;

    remote_call_with_session(session, ^{
        if (r_is_objc_ptr(demoSwitch)) demo = (ig_get(demoSwitch, @"isOn") & 0xFF) != 0;
        if (r_is_objc_ptr(gridSwitch)) grid = (ig_get(gridSwitch, @"isOn") & 0xFF) != 0;
        if (r_is_objc_ptr(hideSwitch)) hide = (ig_get(hideSwitch, @"isOn") & 0xFF) != 0;
        if (r_is_objc_ptr(widthSegments)) {
            uint64_t index = ig_get(widthSegments, @"selectedSegmentIndex");
            if (index <= 7) widthIndex = (NSInteger)index;
        }
        if (r_is_objc_ptr(alphaSegments)) {
            uint64_t index = ig_get(alphaSegments, @"selectedSegmentIndex");
            if (index <= 4) alphaIndex = (NSInteger)index;
        }
        if (r_is_objc_ptr(anchorSegments)) {
            uint64_t index = ig_get(anchorSegments, @"selectedSegmentIndex");
            if (index <= 2) anchor = (NSInteger)index;
        }
    });

    if (demo != _demoEnabled) { _demoEnabled = demo; _needsPush = YES; }
    if (grid != _gridEnabled) { _gridEnabled = grid; _needsPush = YES; }
    if (widthIndex != _widthIndex) {
        _widthIndex = widthIndex;
        _lineWidth = (CGFloat)(widthIndex + 1);
        _needsPush = YES;
    }
    if (alphaIndex != _alphaIndex) {
        _alphaIndex = alphaIndex;
        _canvasAlpha = kIGAlphaSteps[alphaIndex];
        _needsPush = YES;
    }
    if (anchor != _anchorIndex) {
        _anchorIndex = anchor;
        [self movePanelLocked];
    }

    if (hide) {
        [self hidePanelLocked];
    }
}

- (void)hidePanelLocked
{
    if (_panelHidden) return;
    _panelHidden = YES;

    RemoteCallSession *session = _session;
    uint64_t panelWindow = _panelWindow;
    uint64_t hideSwitch = _switchHide;
    uint64_t bubbleWindow = _bubbleWindow;

    if (session) {
        remote_call_with_session(session, ^{
            ig_main_call(panelWindow, "setUserInteractionEnabled:", 0);
            ig_main_call(hideSwitch, "setOn:", 0);
            ig_main_call(bubbleWindow, "setHidden:", 0);
        });
    }
    _needsPush = YES;
    [self setStatus:@"面板已收起 · 点左上角圆钮恢复"];
    cyanide_log(@"[IMGUI] panel hidden");
}

- (void)showPanelLocked
{
    if (!_panelHidden) return;
    _panelHidden = NO;

    RemoteCallSession *session = _session;
    uint64_t panelWindow = _panelWindow;
    uint64_t restoreSwitch = _switchRestore;
    uint64_t bubbleWindow = _bubbleWindow;

    if (session) {
        remote_call_with_session(session, ^{
            ig_main_call(restoreSwitch, "setOn:", 0);
            ig_main_call(bubbleWindow, "setHidden:", 1);
            ig_main_call(panelWindow, "setUserInteractionEnabled:", 1);
        });
    }
    _needsPush = YES;
    [self setStatus:@"运行中"];
    cyanide_log(@"[IMGUI] panel shown");
}

- (void)movePanelLocked
{
    [self computeLayoutLocked];
    CGRect panelRect = _panelRect;
    CGRect bubbleRect = _bubbleRect;

    RemoteCallSession *session = _session;
    uint64_t panelWindow = _panelWindow;
    uint64_t bubbleWindow = _bubbleWindow;

    if (session) {
        remote_call_with_session(session, ^{
            ig_main_rect(panelWindow, "setFrame:", panelRect);
            ig_main_rect(bubbleWindow, "setFrame:", bubbleRect);
        });
    }
    _needsPush = YES;
    cyanide_log(@"[IMGUI] panel moved to %.0f,%.0f", panelRect.origin.x, panelRect.origin.y);
}

#pragma mark - 渲染

- (void)drawCanvasPrimitivesLocked
{
    [_primitivesLock lock];
    NSArray<IGCanvasItem *> *items = [_primitives copy];
    [_primitivesLock unlock];

    if (items.count == 0) return;

    CGFloat alphaScale = _canvasAlpha / 255.0;

    for (IGCanvasItem *item in items) {
        CGFloat baseAlpha = (CGFloat)((item.color >> 24) & 0xFF) / 255.0;
        uint32_t color = IGColorAlpha(item.color, baseAlpha * alphaScale);

        switch (item.type) {
            case IGDrawCmdTypeLine:
                [_ui.drawList addLineFrom:item.a to:item.b color:color thickness:item.thickness];
                break;
            case IGDrawCmdTypeRect:
                [_ui.drawList addRect:CGRectMake(item.a.x, item.a.y, item.b.x, item.b.y)
                                color:color
                            thickness:item.thickness
                               radius:0.0];
                break;
            case IGDrawCmdTypeCircle:
                [_ui.drawList addCircleAt:item.a radius:item.radius color:color thickness:item.thickness];
                break;
            case IGDrawCmdTypeText:
                [_ui.drawList addText:item.text at:item.a fontSize:item.fontSize color:color];
                break;
            default:
                break;
        }
    }
}

- (void)drawGridLocked
{
    CGSize size = _screenSize;
    uint32_t gridColor = IGColorMake(0.26, 0.59, 0.98, 0.16);
    uint32_t axisColor = IGColorMake(0.26, 0.59, 0.98, 0.42);

    for (CGFloat x = 0.0; x <= size.width; x += 60.0) {
        [_ui.drawList addLineFrom:IGVec2Make(x, 0.0) to:IGVec2Make(x, size.height)
                            color:gridColor
                        thickness:0.5];
    }
    for (CGFloat y = 0.0; y <= size.height; y += 60.0) {
        [_ui.drawList addLineFrom:IGVec2Make(0.0, y) to:IGVec2Make(size.width, y)
                            color:gridColor
                        thickness:0.5];
    }

    CGPoint center = CGPointMake(size.width / 2.0, size.height / 2.0);
    [_ui.drawList addLineFrom:IGVec2Make(center.x - 26.0, center.y)
                            to:IGVec2Make(center.x + 26.0, center.y)
                         color:axisColor
                     thickness:1.0];
    [_ui.drawList addLineFrom:IGVec2Make(center.x, center.y - 26.0)
                            to:IGVec2Make(center.x, center.y + 26.0)
                         color:axisColor
                     thickness:1.0];
    [_ui.drawList addCircleAt:IGVec2Make(center.x, center.y) radius:14.0 color:axisColor thickness:1.0];
}

- (void)drawDemoLocked
{
    CGSize size = _screenSize;
    CGPoint center = CGPointMake(size.width / 2.0, size.height / 2.0);
    CGFloat radius = MIN(size.width, size.height) * 0.30;
    NSUInteger count = 8;

    for (NSUInteger i = 0; i < count; i++) {
        CGFloat angle = (CGFloat)_demoPhase + (CGFloat)i * (CGFloat)M_PI * 2.0 / (CGFloat)count;
        IGVec2 target = IGVec2Make(center.x + cos(angle) * radius,
                                   center.y + sin(angle) * radius);
        [_ui.drawList addLineFrom:IGVec2Make(center.x, center.y)
                                to:target
                             color:IGColorMake(0.26, 0.59, 0.98, 0.75)
                         thickness:_lineWidth];
        [_ui.drawList addCircleAt:target
                           radius:5.0
                            color:IGColorMake(1.0, 0.35, 0.35, 0.90)
                        thickness:1.5];
    }

    CGFloat pulse = 30.0 + 8.0 * (CGFloat)sin(_demoPhase * 2.0);
    [_ui.drawList addCircleAt:IGVec2Make(center.x, center.y)
                        radius:pulse
                         color:IGColorMake(0.26, 0.59, 0.98, 0.35)
                     thickness:1.0];

    NSString *label = [NSString stringWithFormat:@"IMGUI DEMO  %.0f deg", _demoPhase * 180.0 / M_PI];
    [_ui.drawList addText:label
                       at:IGVec2Make(center.x - 70.0, center.y + radius + 18.0)
                 fontSize:11.0
                    color:IGColorMake(0.75, 0.75, 0.75, 0.90)];
}

- (void)drawBubbleLocked
{
    CGRect rect = _bubbleRect;
    IGVec2 center = IGVec2Make(CGRectGetMidX(rect), CGRectGetMidY(rect));

    [_ui.drawList addCircleFilledAt:center
                             radius:kIGBubbleSize / 2.0
                              color:IGColorMake(0.06, 0.06, 0.06, 0.92)];
    [_ui.drawList addCircleAt:center
                       radius:kIGBubbleSize / 2.0
                        color:IGColorMake(0.26, 0.59, 0.98, 0.90)
                    thickness:1.5];
    [_ui.drawList addText:@"IG"
                       at:IGVec2Make(center.x - 8.0, center.y - 7.0)
                 fontSize:12.0
                    color:IGColorMake(1.0, 1.0, 1.0, 0.95)];
}

- (NSData *)renderFrameLocked
{
    NSTimeInterval begin = CACurrentMediaTime();
    CGSize size = _screenSize;

    if (_demoEnabled) {
        _demoPhase += 0.12;
        if (_demoPhase > M_PI * 2.0) _demoPhase -= M_PI * 2.0;
    }

    [_ui beginFrameWithDisplaySize:size];

    [self drawCanvasPrimitivesLocked];
    if (_gridEnabled) [self drawGridLocked];
    if (_demoEnabled) [self drawDemoLocked];

    if (_panelHidden) {
        [self drawBubbleLocked];
    } else {
        [_ui beginWindow:@"Cyanide · ImGui" frame:_panelRect];
        [self buildPanelRowsWithCapture:nil];
        [_ui endWindow];
    }

    [_ui endFrame];
    _lastPrimCount = _ui.drawList.count;

    UIImage *image = [_ui.drawList renderWithSize:size scale:_renderScale];
    if (!image) return nil;

    NSData *png = UIImagePNGRepresentation(image);
    _lastRenderMS = (CACurrentMediaTime() - begin) * 1000.0;
    return png;
}

- (void)renderAndPushLocked
{
    if (_state != IGOverlayStateRunning) return;

    NSData *png = [self renderFrameLocked];
    if (png.length == 0) {
        cyanide_log(@"[IMGUI] render produced no data");
        return;
    }

    NSTimeInterval begin = CACurrentMediaTime();
    BOOL ok = [self pushPNGLocked:png];
    NSTimeInterval elapsed = CACurrentMediaTime() - begin;

    _lastPushAt = CACurrentMediaTime();
    _lastPushMS = elapsed * 1000.0;

    if (ok) {
        if (_lastPushMS > 1.0) {
            double instant = 1000.0 / _lastPushMS;
            _fps = (_fps < 0.1) ? instant : (_fps * 0.8 + instant * 0.2);
        }
        _pushFailures = 0;
    } else {
        _pushFailures += 1;
        cyanide_log(@"[IMGUI] push failed (%d/%d)", _pushFailures, kIGMaxPushFailures);
        if (_pushFailures >= kIGMaxPushFailures) {
            [self setStatus:@"推帧连续失败，已停止"];
            [self teardownLocked];
        }
    }
}

#pragma mark - 远程贴图

- (void)ensureRemoteBufferLocked
{
    if (r_is_objc_ptr(_remoteBuffer) && _remoteBufferCapacity >= kIGRemoteBufferBytes) return;

    RemoteCallSession *session = _session;
    if (!session) return;

    __block uint64_t buffer = 0;
    remote_call_with_session(session, ^{
        buffer = r_dlsym_call(R_TIMEOUT, "malloc", kIGRemoteBufferBytes, 0, 0, 0, 0, 0, 0, 0);
    });

    if (r_is_objc_ptr(buffer)) {
        _remoteBuffer = buffer;
        _remoteBufferCapacity = kIGRemoteBufferBytes;
        cyanide_log(@"[IMGUI] remote buffer 0x%llx (%u bytes)", buffer, kIGRemoteBufferBytes);
    } else {
        cyanide_log(@"[IMGUI] remote malloc failed");
    }
}

- (BOOL)pushPNGLocked:(NSData *)png
{
    RemoteCallSession *session = _session;
    if (!session || png.length == 0) return NO;
    if (!r_is_objc_ptr(_imageView)) return NO;

    if (!r_is_objc_ptr(_remoteBuffer) || _remoteBufferCapacity < png.length) {
        [self ensureRemoteBufferLocked];
        if (!r_is_objc_ptr(_remoteBuffer) || _remoteBufferCapacity < png.length) return NO;
    }

    uint64_t buffer = _remoteBuffer;
    const void *bytes = png.bytes;
    uint64_t length = (uint64_t)png.length;
    CGFloat imageScale = _renderScale;
    uint64_t imageView = _imageView;

    __block BOOL ok = NO;
    uint32_t previousSettle = r_settle_us(kIGSettleMicroseconds);

    remote_call_with_session(session, ^{
        if (!remote_write(buffer, bytes, length)) {
            cyanide_log(@"[IMGUI] remote_write failed len=%llu", length);
            return;
        }

        // NSData 从远程缓冲区拷一份，再交给 ImageIO 解码成 UIImage。
        uint64_t nsdata = r_msg2_main_raw(ig_class(@"NSData"), "dataWithBytes:length:",
                                          &buffer, sizeof(buffer),
                                          &length, sizeof(length),
                                          NULL, 0, NULL, 0);
        if (!r_is_objc_ptr(nsdata)) return;

        double scale = (double)imageScale;
        uint64_t image = r_msg2_main_raw(ig_class(@"UIImage"), "imageWithData:scale:",
                                         &nsdata, sizeof(nsdata),
                                         &scale, sizeof(scale),
                                         NULL, 0, NULL, 0);
        if (!r_is_objc_ptr(image)) return;

        ig_main_call(imageView, "setImage:", image);
        ok = YES;
    });

    r_settle_us(previousSettle);

    if (ok) _imagePushVerified = YES;
    return ok;
}

- (void)installFallbackLabelLocked
{
    RemoteCallSession *session = _session;
    uint64_t panelWindow = _panelWindow;
    if (!session || !r_is_objc_ptr(panelWindow)) return;

    CGRect frame = CGRectMake(8.0, 8.0, kIGPanelWidth - 16.0, 60.0);
    NSString *text = @"ImGui 推图失败\n看 Cyanide 日志 [IMGUI]";

    __block uint64_t label = 0;
    remote_call_with_session(session, ^{
        uint64_t cls = ig_class(@"UILabel");
        uint64_t alloc = r_msg2_main(cls, "alloc", 0, 0, 0, 0);
        label = r_is_objc_ptr(alloc)
            ? r_msg2_main_raw(alloc, "initWithFrame:", &frame, sizeof(frame),
                              NULL, 0, NULL, 0, NULL, 0)
            : 0;
        if (!r_is_objc_ptr(label)) return;

        ig_main_call(label, "setNumberOfLines:", 2);
        uint64_t string = ig_nsstring(text);
        if (r_is_objc_ptr(string)) {
            ig_main_call(label, "setText:", string);
            ig_release(string);
        }
        uint64_t white = r_msg2_main(ig_class(@"UIColor"), "whiteColor", 0, 0, 0, 0);
        if (r_is_objc_ptr(white)) ig_main_call(label, "setTextColor:", white);
        ig_main_call(panelWindow, "addSubview:", label);
    });

    _fallbackLabel = label;
}

#pragma mark - 画布 API

- (void)appendPrimitive:(IGCanvasItem *)item
{
    if (!item) return;
    [_primitivesLock lock];
    if (_primitives.count > 4096) {
        [_primitives removeAllObjects];
    }
    [_primitives addObject:item];
    [_primitivesLock unlock];
    _needsPush = YES;
}

- (void)clearCanvas
{
    [_primitivesLock lock];
    [_primitives removeAllObjects];
    [_primitivesLock unlock];
    _needsPush = YES;
}

- (void)drawLineFrom:(CGPoint)from to:(CGPoint)to color:(UIColor *)color width:(CGFloat)width
{
    IGCanvasItem *item = [[IGCanvasItem alloc] init];
    item.type = IGDrawCmdTypeLine;
    item.a = IGVec2Make(from.x, from.y);
    item.b = IGVec2Make(to.x, to.y);
    item.color = ig_color_argb(color ?: [UIColor whiteColor]);
    item.thickness = MAX(0.5, width);
    [self appendPrimitive:item];
}

- (void)drawRect:(CGRect)rect color:(UIColor *)color width:(CGFloat)width
{
    IGCanvasItem *item = [[IGCanvasItem alloc] init];
    item.type = IGDrawCmdTypeRect;
    item.a = IGVec2Make(rect.origin.x, rect.origin.y);
    item.b = IGVec2Make(rect.size.width, rect.size.height);
    item.color = ig_color_argb(color ?: [UIColor whiteColor]);
    item.thickness = MAX(0.5, width);
    [self appendPrimitive:item];
}

- (void)drawCircleAt:(CGPoint)center radius:(CGFloat)radius color:(UIColor *)color width:(CGFloat)width
{
    IGCanvasItem *item = [[IGCanvasItem alloc] init];
    item.type = IGDrawCmdTypeCircle;
    item.a = IGVec2Make(center.x, center.y);
    item.radius = MAX(0.5, radius);
    item.color = ig_color_argb(color ?: [UIColor whiteColor]);
    item.thickness = MAX(0.5, width);
    [self appendPrimitive:item];
}

- (void)drawText:(NSString *)text at:(CGPoint)point size:(CGFloat)size color:(UIColor *)color
{
    if (text.length == 0) return;
    IGCanvasItem *item = [[IGCanvasItem alloc] init];
    item.type = IGDrawCmdTypeText;
    item.a = IGVec2Make(point.x, point.y);
    item.text = text;
    item.fontSize = MAX(6.0, size);
    item.color = ig_color_argb(color ?: [UIColor whiteColor]);
    [self appendPrimitive:item];
}

- (void)requestRedraw
{
    _needsPush = YES;
}

- (BOOL)demoEnabled
{
    return _demoEnabled;
}

- (void)setDemoEnabled:(BOOL)enabled
{
    _demoEnabled = enabled;
    _needsPush = YES;
}

- (BOOL)gridEnabled
{
    return _gridEnabled;
}

- (void)setGridEnabled:(BOOL)enabled
{
    _gridEnabled = enabled;
    _needsPush = YES;
}

@end
