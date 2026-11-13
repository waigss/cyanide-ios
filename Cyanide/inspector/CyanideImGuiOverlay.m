//
//  CyanideImGuiOverlay.m
//  Cyanide
//
//  v3：位图传输。
//
//  三块「远程位图视图」（CyanidePixelView），每块自己建窗口 + UIImageView，
//  本进程把一帧画进 BGRA 缓冲，memcpy 进远程 CGBitmapContext，再让远程
//  CGImage → UIImage → 主线程 setImage:。每帧 6 次单条远程调用，带宽是一次
//  memcpy。
//
//      canvasView  level 1e6     全屏 1x   网格 / 演示 / 用户折线   点击穿透
//      panelView   level 1e6+1   面板 2x   ImGui 面板              隐形控件挂这儿
//      bubbleView  level 1e6+1   圆钮 2x    收起后的恢复按钮
//
//  为什么不是 v2 的 CAShapeLayer 路径：那条路只能表达描边，写不了文字和填充，
//  而且把「画什么」绑死在 CGPath 上。位图这条路什么都能画，代价只是一次拷贝。
//

#import "CyanideImGuiOverlay.h"

#import "CyanidePixelView.h"
#import "../imgui/IGUI.h"
#import "../imgui/IGDrawList.h"
#import "../TaskRop/RemoteCall.h"
#import "../tweaks/remote_objc.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/kutils.h"
#import "../DSKeepAlive.h"
#import "../SettingsViewController.h"
#import "CyanideLog.h"

#import <QuartzCore/QuartzCore.h>
#import <math.h>
#import <string.h>

#pragma mark - 常量

static const CGFloat kIGPanelWidth = 252.0;
static const CGFloat kIGPanelMargin = 10.0;
static const CGFloat kIGPanelTop = 64.0;
static const CGFloat kIGBubbleSize = 38.0;
static const CGFloat kIGCanvasLevel = 1000000.0;
static const CGFloat kIGPanelLevel = 1000001.0;
static const CGFloat kIGMaxRenderScale = 2.0;

static const NSTimeInterval kIGTickInterval = 1.0 / 60.0;
static const NSTimeInterval kIGPollInterval = 0.066;
static const NSTimeInterval kIGPanelPushInterval = 0.10;

static const CGFloat kIGAlphaSteps[5] = {40.0, 95.0, 150.0, 205.0, 255.0};
static const NSInteger kIGFPSSteps[3] = {15, 30, 60};

#pragma mark - 远程小工具（单次调用）

static NSMutableDictionary<NSString *, NSNumber *> *gIGClassCache = nil;
static NSMutableDictionary<NSString *, NSNumber *> *gIGSelectorCache = nil;

static void ig_cache_init(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gIGClassCache = [NSMutableDictionary dictionaryWithCapacity:16];
        gIGSelectorCache = [NSMutableDictionary dictionaryWithCapacity:64];
    });
}

static void ig_cache_reset(void)
{
    ig_cache_init();
    [gIGClassCache removeAllObjects];
    [gIGSelectorCache removeAllObjects];
}

static uint64_t ig_class(NSString *name)
{
    ig_cache_init();
    NSNumber *cached = gIGClassCache[name];
    if (cached) return cached.unsignedLongLongValue;
    uint64_t value = r_class(name.UTF8String);
    if (value) gIGClassCache[name] = @(value);
    return value;
}

static uint64_t ig_sel(NSString *name)
{
    ig_cache_init();
    NSNumber *cached = gIGSelectorCache[name];
    if (cached) return cached.unsignedLongLongValue;
    uint64_t value = r_sel(name.UTF8String);
    if (value) gIGSelectorCache[name] = @(value);
    return value;
}

static uint64_t ig_msg(uint64_t obj, NSString *selName, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!r_is_objc_ptr(obj)) return 0;
    uint64_t sel = ig_sel(selName);
    if (!sel) return 0;
    return r_msg(obj, sel, a0, a1, a2, a3);
}

static uint64_t ig_get(uint64_t obj, NSString *selName)
{
    return ig_msg(obj, selName, 0, 0, 0, 0);
}

static void ig_set_rect(uint64_t obj, const char *selName, CGRect rect)
{
    if (!r_is_objc_ptr(obj) || !selName) return;
    r_msg2_main_raw(obj, selName, &rect, sizeof(rect), NULL, 0, NULL, 0, NULL, 0);
}

static void ig_set_double(uint64_t obj, const char *selName, double value)
{
    if (!r_is_objc_ptr(obj) || !selName) return;
    r_msg2_main_raw(obj, selName, &value, sizeof(value), NULL, 0, NULL, 0, NULL, 0);
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

// 隐形控件：alpha 0.02 —— UIKit 的 hitTest 只忽略 alpha < 0.01，所以还能点
static uint64_t ig_make_switch(uint64_t parent, CGRect frame, BOOL on)
{
    uint64_t cls = ig_class(@"UISwitch");
    if (!r_is_objc_ptr(cls)) return 0;

    uint64_t alloc = ig_msg(cls, @"alloc", 0, 0, 0, 0);
    uint64_t control = r_is_objc_ptr(alloc) ? ig_msg(alloc, @"init", 0, 0, 0, 0) : 0;
    if (!r_is_objc_ptr(control)) return 0;

    ig_set_rect(control, "setFrame:", frame);
    ig_set_double(control, "setAlpha:", 0.02);
    ig_msg(control, @"setOn:", on ? 1 : 0, 0, 0, 0);

    uint64_t clear = ig_msg(ig_class(@"UIColor"), @"clearColor", 0, 0, 0, 0);
    if (r_is_objc_ptr(clear)) {
        ig_msg(control, @"setOnTintColor:", clear, 0, 0, 0);
        ig_msg(control, @"setThumbTintColor:", clear, 0, 0, 0);
    }

    ig_msg(parent, @"addSubview:", control, 0, 0, 0);
    return control;
}

static uint64_t ig_make_segments(uint64_t parent, CGRect frame, NSArray<NSString *> *labels, NSInteger active)
{
    uint64_t cls = ig_class(@"UISegmentedControl");
    if (!r_is_objc_ptr(cls)) return 0;

    uint64_t alloc = ig_msg(cls, @"alloc", 0, 0, 0, 0);
    if (!r_is_objc_ptr(alloc)) return 0;

    uint64_t control = r_msg2_main_raw(alloc, "initWithFrame:", &frame, sizeof(frame),
                                       NULL, 0, NULL, 0, NULL, 0);
    if (!r_is_objc_ptr(control)) return 0;

    ig_set_double(control, "setAlpha:", 0.02);
    for (NSString *label in labels) {
        uint64_t text = ig_nsstring(label);
        if (!r_is_objc_ptr(text)) continue;
        ig_msg(control, @"insertSegmentWithTitle:animated:", text, 0, 0, 0);
        ig_release(text);
    }
    ig_msg(control, @"setSelectedSegmentIndex:", (uint64_t)MAX((NSInteger)0, active), 0, 0, 0);

    ig_msg(parent, @"addSubview:", control, 0, 0, 0);
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

    CyanidePixelView *_canvasView;
    CyanidePixelView *_panelView;
    CyanidePixelView *_bubbleView;

    uint64_t _switchDemo;
    uint64_t _switchGrid;
    uint64_t _switchHide;
    uint64_t _switchRestore;
    uint64_t _segWidth;
    uint64_t _segAlpha;
    uint64_t _segFPS;
    uint64_t _segAnchor;

    BOOL _panelHidden;
    BOOL _panelDirty;
    BOOL _canvasDirty;
    BOOL _busy;

    NSTimeInterval _lastPollAt;
    NSTimeInterval _lastCanvasAt;
    NSTimeInterval _lastPanelAt;
    double _canvasMS;
    double _canvasFPS;
    double _panelMS;
    NSUInteger _canvasCalls;
    NSUInteger _panelCalls;
    double _demoPhase;

    CGFloat _lineWidth;
    UIColor *_strokeColor;
    NSInteger _widthIndex;
    NSInteger _alphaIndex;
    NSInteger _fpsIndex;
    NSInteger _anchorIndex;

    BOOL _demoEnabled;
    BOOL _gridEnabled;

    NSMutableArray<NSArray<NSValue *> *> *_userStrips;
    NSLock *_stripsLock;

    IGUI *_ui;
    NSString *_statusLine;
}

+ (instancetype)sharedOverlay
{
    static CyanideImGuiOverlay *shared = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        shared = [[CyanideImGuiOverlay alloc] init];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.cyanide.imguioverlay", DISPATCH_QUEUE_SERIAL);
        _userStrips = [NSMutableArray array];
        _stripsLock = [[NSLock alloc] init];
        _ui = [[IGUI alloc] init];

        IGStyle style = _ui.style;
        style.itemSpacingY = 3.0;
        _ui.style = style;

        _renderScale = kIGMaxRenderScale;
        _widthIndex = 1;
        _alphaIndex = 4;
        _fpsIndex = 1;                          // 30fps
        _anchorIndex = 0;
        _lineWidth = (CGFloat)(_widthIndex + 1);
        _strokeColor = [UIColor colorWithRed:0.26 green:0.59 blue:0.98 alpha:1.0];
        _demoEnabled = NO;
        _gridEnabled = NO;
        _state = IGOverlayStateIdle;
        _statusLine = @"未启动";
    }
    return self;
}

- (BOOL)isActive { return _state == IGOverlayStateRunning; }
- (BOOL)isStarting { return _state == IGOverlayStateStarting; }

- (NSString *)statusLine
{
    @synchronized (self) { return _statusLine ?: @""; }
}

- (void)setStatus:(NSString *)line
{
    @synchronized (self) { _statusLine = [line copy]; }
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
    _renderScale = MIN(MAX(screenScale, 1.0), kIGMaxRenderScale);

    [self setStatus:@"正在挂载…"];
    cyanide_log(@"[IMGUI] start: screen=%.0fx%.0f scale=%.1f",
                _screenSize.width, _screenSize.height, _renderScale);

    ds_keepalive_apply_enabled(YES);

    dispatch_async(_queue, ^{ [self installLocked]; });
}

- (void)stop
{
    dispatch_async(_queue, ^{ [self teardownLocked]; });
}

- (void)installLocked
{
    if (!kexploit_krw_ready() && !settings_ensure_kernel_ready()) {
        [self setStatus:@"内核未就绪"];
        @synchronized (self) { _state = IGOverlayStateFailed; }
        return;
    }

    ig_cache_reset();

    RemoteCallSession *session =
        [[RemoteCallSession alloc] initWithProcess:@"SpringBoard"
                               useMigFilterBypass:NO
                          firstExceptionTimeoutMS:12000];
    if (!session) {
        [self setStatus:[NSString stringWithFormat:@"SpringBoard 会话失败 (%d)",
                         (int)remote_call_last_init_failure()]];
        @synchronized (self) { _state = IGOverlayStateFailed; }
        return;
    }
    _session = session;
    cyanide_log(@"[IMGUI] session ok pid=%d", session.pid);

    [self computeLayoutLocked];

    uint64_t scene = 0;
    {
        __block uint64_t foundScene = 0;
        remote_call_with_session(session, ^{
            uint64_t app = ig_msg(ig_class(@"UIApplication"), @"sharedApplication", 0, 0, 0, 0);
            if (!r_is_objc_ptr(app)) return;
            uint64_t keyWindow = ig_msg(app, @"keyWindow", 0, 0, 0, 0);
            if (!r_is_objc_ptr(keyWindow)) {
                uint64_t windows = ig_msg(app, @"windows", 0, 0, 0, 0);
                uint64_t count = r_is_objc_ptr(windows) ? ig_msg(windows, @"count", 0, 0, 0, 0) : 0;
                if (count > 0 && count < 64) {
                    keyWindow = ig_msg(windows, @"objectAtIndex:", 0, 0, 0, 0);
                }
            }
            if (r_is_objc_ptr(keyWindow)) foundScene = ig_msg(keyWindow, @"windowScene", 0, 0, 0, 0);
        });
        scene = foundScene;
    }

    CGRect screenRect = CGRectMake(0.0, 0.0, _screenSize.width, _screenSize.height);
    CGRect panelRect = _panelRect;
    CGRect bubbleRect = _bubbleRect;

    _canvasView = [CyanidePixelView viewWithSession:session
                                              scene:scene
                                              frame:screenRect
                                              level:kIGCanvasLevel
                                              scale:1.0];
    if (!_canvasView) {
        [self setStatus:@"画布创建失败"];
        [self teardownLocked];
        @synchronized (self) { _state = IGOverlayStateFailed; }
        return;
    }

    _panelView = [CyanidePixelView viewWithSession:session
                                            scene:scene
                                            frame:panelRect
                                            level:kIGPanelLevel
                                            scale:_renderScale];
    if (!_panelView) {
        [self setStatus:@"面板创建失败"];
        [self teardownLocked];
        @synchronized (self) { _state = IGOverlayStateFailed; }
        return;
    }

    _bubbleView = [CyanidePixelView viewWithSession:session
                                             scene:scene
                                             frame:bubbleRect
                                             level:kIGPanelLevel
                                             scale:_renderScale];

    // 控件挂到面板窗口里（窗口坐标 = 屏幕坐标 - 面板原点）
    __block CGRect rowDemo = CGRectZero, rowGrid = CGRectZero, rowHide = CGRectZero;
    __block CGRect rowWidth = CGRectZero, rowAlpha = CGRectZero, rowFPS = CGRectZero;
    __block CGRect rowAnchor = CGRectZero;

    [self captureControlRectsLocked:^(NSString *key, CGRect rect) {
        if ([key isEqualToString:@"demo"]) rowDemo = rect;
        else if ([key isEqualToString:@"grid"]) rowGrid = rect;
        else if ([key isEqualToString:@"hide"]) rowHide = rect;
        else if ([key isEqualToString:@"width"]) rowWidth = rect;
        else if ([key isEqualToString:@"alpha"]) rowAlpha = rect;
        else if ([key isEqualToString:@"fps"]) rowFPS = rect;
        else if ([key isEqualToString:@"anchor"]) rowAnchor = rect;
    }];

    CGFloat offsetX = -panelRect.origin.x;
    CGFloat offsetY = -panelRect.origin.y;
    uint64_t panelWindow = _panelView.window;

    BOOL demoOn = _demoEnabled;
    BOOL gridOn = _gridEnabled;
    NSInteger widthIndex = _widthIndex;
    NSInteger alphaIndex = _alphaIndex;
    NSInteger fpsIndex = _fpsIndex;
    NSInteger anchorIndex = _anchorIndex;

    __block uint64_t swDemo = 0, swGrid = 0, swHide = 0, swRestore = 0;
    __block uint64_t segWidth = 0, segAlpha = 0, segFPS = 0, segAnchor = 0;

    {
        __block uint64_t bubbleWindow = _bubbleView ? _bubbleView.window : 0;
        uint32_t previousSettle = r_settle_us(8000);
        remote_call_with_session(session, ^{
            swDemo = ig_make_switch(panelWindow, CGRectOffset(rowDemo, offsetX, offsetY), demoOn);
            swGrid = ig_make_switch(panelWindow, CGRectOffset(rowGrid, offsetX, offsetY), gridOn);
            swHide = ig_make_switch(panelWindow, CGRectOffset(rowHide, offsetX, offsetY), NO);
            segWidth = ig_make_segments(panelWindow, CGRectOffset(rowWidth, offsetX, offsetY),
                                        @[@"1", @"2", @"3", @"4", @"5", @"6", @"7", @"8"], widthIndex);
            segAlpha = ig_make_segments(panelWindow, CGRectOffset(rowAlpha, offsetX, offsetY),
                                        @[@"40", @"95", @"150", @"205", @"255"], alphaIndex);
            segFPS = ig_make_segments(panelWindow, CGRectOffset(rowFPS, offsetX, offsetY),
                                      @[@"15", @"30", @"60"], fpsIndex);
            segAnchor = ig_make_segments(panelWindow, CGRectOffset(rowAnchor, offsetX, offsetY),
                                         @[@"Top", @"Right", @"Bottom"], anchorIndex);
            if (r_is_objc_ptr(bubbleWindow)) {
                CGRect restoreFrame = CGRectMake(0.0, 0.0, kIGBubbleSize, kIGBubbleSize);
                swRestore = ig_make_switch(bubbleWindow, restoreFrame, NO);
                ig_msg(bubbleWindow, @"setHidden:", 1, 0, 0, 0);
            }
        });
        r_settle_us(previousSettle);
    }

    _switchDemo = swDemo;
    _switchGrid = swGrid;
    _switchHide = swHide;
    _switchRestore = swRestore;
    _segWidth = segWidth;
    _segAlpha = segAlpha;
    _segFPS = segFPS;
    _segAnchor = segAnchor;

    [self blitBubbleLocked];
    [self blitPanelLocked];
    [self blitCanvasLocked];

    [self startTimerLocked];
    [self setStatus:[NSString stringWithFormat:@"运行中 · %.0f×%.0f", _screenSize.width, _screenSize.height]];
    @synchronized (self) { _state = IGOverlayStateRunning; }
    cyanide_log(@"[IMGUI] running canvas=0x%llx panel=0x%llx bubble=0x%llx",
                _canvasView.imageView, _panelView.imageView,
                _bubbleView ? _bubbleView.imageView : 0);
}

- (void)teardownLocked
{
    if (_timer) {
        dispatch_source_cancel(_timer);
        _timer = nil;
    }

    [_canvasView detach];
    [_panelView detach];
    [_bubbleView detach];
    _canvasView = nil;
    _panelView = nil;
    _bubbleView = nil;

    _switchDemo = 0;
    _switchGrid = 0;
    _switchHide = 0;
    _switchRestore = 0;
    _segWidth = 0;
    _segAlpha = 0;
    _segFPS = 0;
    _segAnchor = 0;
    _panelHidden = NO;
    _panelDirty = NO;
    _canvasDirty = NO;
    _session = nil;

    @synchronized (self) { _state = IGOverlayStateIdle; }
    [self setStatus:@"已停止"];
    cyanide_log(@"[IMGUI] stopped");
}

- (void)startTimerLocked
{
    if (_timer) return;
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    if (!timer) return;

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_timer(timer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kIGTickInterval * NSEC_PER_SEC)),
                              (uint64_t)(kIGTickInterval * NSEC_PER_SEC),
                              (uint64_t)(0.002 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(timer, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        [strongSelf tick];
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
    if (_anchorIndex == 2) originY = MAX(kIGPanelTop, screenH - panelHeight - 110.0);

    _panelRect = CGRectMake(originX, originY, kIGPanelWidth, panelHeight);
    _bubbleRect = CGRectMake(originX, originY, kIGBubbleSize, kIGBubbleSize);
}

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

    [ui text:[NSString stringWithFormat:@"%.0f fps · %lu calls · %.1fms",
              _canvasFPS, (unsigned long)_canvasCalls, _canvasMS]];
    [ui textDisabled:[NSString stringWithFormat:@"panel %.1fms   sink %ld",
                      _panelMS, (long)kIGFPSSteps[_fpsIndex]]];
    [ui separator];

    [ui checkbox:@"Demo lines" value:_demoEnabled];
    if (capture) capture(@"demo", ui.lastItemRect);

    [ui checkbox:@"Grid" value:_gridEnabled];
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
             valueText:[NSString stringWithFormat:@"%.0f", kIGAlphaSteps[_alphaIndex]]];
    if (capture) capture(@"alpha", ui.lastItemRect);

    [ui sliderIntTicks:@"FPS cap"
                 value:_fpsIndex
                   min:0
                   max:2
             valueText:[NSString stringWithFormat:@"%ld", (long)kIGFPSSteps[_fpsIndex]]];
    if (capture) capture(@"fps", ui.lastItemRect);

    [ui separator];

    [ui tabBar:@[@"Top", @"Right", @"Bottom"] active:_anchorIndex];
    if (capture) capture(@"anchor", ui.lastItemRect);

    [ui button:@"Hide panel"];
    if (capture) capture(@"hide", ui.lastItemRect);

    [ui textDisabled:@"canvas: click-through"];
}

#pragma mark - 帧循环

- (void)tick
{
    if (_state != IGOverlayStateRunning) return;
    if (_busy) return;

    _busy = YES;
    @try {
        NSTimeInterval now = CACurrentMediaTime();

        if (now - _lastPollAt >= kIGPollInterval) {
            _lastPollAt = now;
            [self pollLocked];
        }

        NSInteger targetFPS = MAX((NSInteger)1, kIGFPSSteps[_fpsIndex]);
        NSTimeInterval interval = 1.0 / (NSTimeInterval)targetFPS;

        if ((_demoEnabled || _canvasDirty) && (now - _lastCanvasAt) >= interval) {
            _lastCanvasAt = now;
            _canvasDirty = NO;
            if (_demoEnabled) {
                _demoPhase += 1.6 / (double)targetFPS;
                if (_demoPhase > M_PI * 2.0) _demoPhase -= M_PI * 2.0;
            }
            [self blitCanvasLocked];
        }

        if (_panelDirty && !_panelHidden && (now - _lastPanelAt) >= kIGPanelPushInterval) {
            _lastPanelAt = now;
            _panelDirty = NO;
            [self blitPanelLocked];
        }
    } @finally {
        _busy = NO;
    }
}

#pragma mark - 绘制

- (uint32_t)strokeColorValueLocked
{
    CGFloat r = 1.0, g = 1.0, b = 1.0, a = 1.0;
    if (![_strokeColor getRed:&r green:&g blue:&b alpha:&a]) {
        CGFloat white = 1.0;
        CGFloat alpha = 1.0;
        if ([_strokeColor getWhite:&white alpha:&alpha]) {
            r = g = b = white;
            a = alpha;
        }
    }
    return IGColorMake(r, g, b, a * (kIGAlphaSteps[_alphaIndex] / 255.0));
}

- (void)drawGridLocked
{
    CGSize size = _screenSize;
    uint32_t color = IGColorMake(1.0, 1.0, 1.0, 0.14);
    CGFloat step = 64.0;

    for (CGFloat x = 0.0; x <= size.width; x += step) {
        [_ui.drawList addLineFrom:IGVec2Make(x, 0.0) to:IGVec2Make(x, size.height)
                            color:color thickness:0.5];
    }
    for (CGFloat y = 0.0; y <= size.height; y += step) {
        [_ui.drawList addLineFrom:IGVec2Make(0.0, y) to:IGVec2Make(size.width, y)
                            color:color thickness:0.5];
    }
}

- (void)drawUserStripsLocked
{
    [_stripsLock lock];
    NSArray<NSArray<NSValue *> *> *strips = [_userStrips copy];
    [_stripsLock unlock];
    if (strips.count == 0) return;

    uint32_t color = [self strokeColorValueLocked];
    CGFloat thickness = _lineWidth;

    for (NSArray<NSValue *> *strip in strips) {
        if (strip.count < 2) continue;
        CGPoint previous = strip[0].CGPointValue;
        for (NSUInteger i = 1; i < strip.count; i++) {
            CGPoint point = strip[i].CGPointValue;
            [_ui.drawList addLineFrom:IGVec2Make(previous.x, previous.y)
                                   to:IGVec2Make(point.x, point.y)
                                color:color
                            thickness:thickness];
            previous = point;
        }
    }
}

- (void)drawDemoLocked
{
    CGSize size = _screenSize;
    CGPoint center = CGPointMake(size.width / 2.0, size.height / 2.0);
    CGFloat radius = MIN(size.width, size.height) * 0.30;
    uint32_t color = [self strokeColorValueLocked];
    CGFloat thickness = MAX(1.0, _lineWidth);

    for (NSInteger i = 0; i < 8; i++) {
        CGFloat angle = (CGFloat)_demoPhase + (CGFloat)i * (CGFloat)M_PI / 4.0;
        [_ui.drawList addLineFrom:IGVec2Make(center.x, center.y)
                               to:IGVec2Make(center.x + cos(angle) * radius,
                                             center.y + sin(angle) * radius)
                            color:color
                        thickness:thickness];
    }

    CGFloat ringRadius = 42.0 + 9.0 * (CGFloat)sin(_demoPhase * 2.0);
    uint32_t ringColor = IGColorMake(1.0, 1.0, 1.0, 0.45);
    CGPoint previous = CGPointMake(center.x + ringRadius, center.y);
    for (NSInteger i = 1; i <= 48; i++) {
        CGFloat angle = (CGFloat)i * 2.0 * (CGFloat)M_PI / 48.0;
        CGPoint point = CGPointMake(center.x + cos(angle) * ringRadius,
                                    center.y + sin(angle) * ringRadius);
        [_ui.drawList addLineFrom:IGVec2Make(previous.x, previous.y)
                               to:IGVec2Make(point.x, point.y)
                            color:ringColor
                        thickness:1.5];
        previous = point;
    }
}

- (void)blitCanvasLocked
{
    if (!_canvasView) return;

    IGDrawList *list = _ui.drawList;
    [_ui beginFrameWithDisplaySize:_screenSize];
    if (_gridEnabled) [self drawGridLocked];
    [self drawUserStripsLocked];
    if (_demoEnabled) [self drawDemoLocked];
    [_ui endFrame];

    [_canvasView blitWithScale:1.0 draw:^(CGContextRef ctx, CGSize pointSize) {
        [list drawIntoContext:ctx];
    }];

    _canvasCalls = _canvasView.lastCallCount;
    _canvasMS = _canvasView.lastUpdateMS;
    if (_canvasMS > 0.05) {
        double instant = 1000.0 / _canvasMS;
        _canvasFPS = (_canvasFPS < 1.0) ? instant : (_canvasFPS * 0.8 + instant * 0.2);
    }
}

- (void)blitPanelLocked
{
    if (!_panelView) return;

    IGDrawList *list = _ui.drawList;
    CGRect rect = _panelRect;

    [_ui beginFrameWithDisplaySize:_screenSize];
    [_ui beginWindow:@"Cyanide · ImGui" frame:rect];
    [self buildPanelRowsWithCapture:nil];
    [_ui endWindow];
    [_ui endFrame];

    NSTimeInterval begin = CACurrentMediaTime();
    [_panelView blitWithScale:_renderScale draw:^(CGContextRef ctx, CGSize pointSize) {
        CGContextTranslateCTM(ctx, -rect.origin.x, -rect.origin.y);
        [list drawIntoContext:ctx];
    }];
    _panelCalls = _panelView.lastCallCount;
    _panelMS = (CACurrentMediaTime() - begin) * 1000.0;
}

- (void)blitBubbleLocked
{
    if (!_bubbleView) return;

    IGDrawList *list = _ui.drawList;
    CGFloat half = kIGBubbleSize / 2.0;

    [_ui beginFrameWithDisplaySize:CGSizeMake(kIGBubbleSize, kIGBubbleSize)];
    [list addCircleFilledAt:IGVec2Make(half, half)
                     radius:half - 1.5
                      color:IGColorMake(0.06, 0.06, 0.06, 0.92)];
    [list addCircleAt:IGVec2Make(half, half)
               radius:half - 1.5
                color:IGColorMake(0.26, 0.59, 0.98, 0.95)
            thickness:1.5];
    [list addText:@"IG"
               at:IGVec2Make(half - 9.0, half - 7.0)
         fontSize:12.0
            color:IGColorMake(1.0, 1.0, 1.0, 0.95)];
    [_ui endFrame];

    [_bubbleView blitWithScale:_renderScale draw:^(CGContextRef ctx, CGSize pointSize) {
        [list drawIntoContext:ctx];
    }];
}

#pragma mark - 轮询

- (void)pollLocked
{
    RemoteCallSession *session = _session;
    if (!session) return;

    if (_panelHidden) {
        uint64_t restoreSwitch = _switchRestore;
        __block BOOL restore = NO;
        remote_call_with_session(session, ^{
            if (r_is_objc_ptr(restoreSwitch)) restore = (ig_get(restoreSwitch, @"isOn") & 0xFF) != 0;
        });
        if (restore) [self showPanelLocked];
        return;
    }

    uint64_t demoSwitch = _switchDemo;
    uint64_t gridSwitch = _switchGrid;
    uint64_t hideSwitch = _switchHide;
    uint64_t widthSeg = _segWidth;
    uint64_t alphaSeg = _segAlpha;
    uint64_t fpsSeg = _segFPS;
    uint64_t anchorSeg = _segAnchor;

    __block BOOL demo = NO, grid = NO, hide = NO;
    __block NSInteger width = _widthIndex, alpha = _alphaIndex;
    __block NSInteger fps = _fpsIndex, anchor = _anchorIndex;

    remote_call_with_session(session, ^{
        if (r_is_objc_ptr(demoSwitch)) demo = (ig_get(demoSwitch, @"isOn") & 0xFF) != 0;
        if (r_is_objc_ptr(gridSwitch)) grid = (ig_get(gridSwitch, @"isOn") & 0xFF) != 0;
        if (r_is_objc_ptr(hideSwitch)) hide = (ig_get(hideSwitch, @"isOn") & 0xFF) != 0;

        if (r_is_objc_ptr(widthSeg)) {
            uint64_t index = ig_get(widthSeg, @"selectedSegmentIndex");
            if (index <= 7) width = (NSInteger)index;
        }
        if (r_is_objc_ptr(alphaSeg)) {
            uint64_t index = ig_get(alphaSeg, @"selectedSegmentIndex");
            if (index <= 4) alpha = (NSInteger)index;
        }
        if (r_is_objc_ptr(fpsSeg)) {
            uint64_t index = ig_get(fpsSeg, @"selectedSegmentIndex");
            if (index <= 2) fps = (NSInteger)index;
        }
        if (r_is_objc_ptr(anchorSeg)) {
            uint64_t index = ig_get(anchorSeg, @"selectedSegmentIndex");
            if (index <= 2) anchor = (NSInteger)index;
        }
    });

    if (demo != _demoEnabled) {
        _demoEnabled = demo;
        _canvasDirty = YES;
        _panelDirty = YES;
    }
    if (grid != _gridEnabled) {
        _gridEnabled = grid;
        _canvasDirty = YES;
        _panelDirty = YES;
    }
    if (width != _widthIndex) {
        _widthIndex = width;
        _lineWidth = (CGFloat)(width + 1);
        _canvasDirty = YES;
        _panelDirty = YES;
    }
    if (alpha != _alphaIndex) {
        _alphaIndex = alpha;
        _canvasDirty = YES;
        _panelDirty = YES;
    }
    if (fps != _fpsIndex) {
        _fpsIndex = fps;
        _panelDirty = YES;
    }
    if (anchor != _anchorIndex) {
        _anchorIndex = anchor;
        [self movePanelLocked];
    }

    if (hide) [self hidePanelLocked];
}

- (void)hidePanelLocked
{
    if (_panelHidden) return;
    _panelHidden = YES;

    RemoteCallSession *session = _session;
    uint64_t panelWindow = _panelView ? _panelView.window : 0;
    uint64_t bubbleWindow = _bubbleView ? _bubbleView.window : 0;
    uint64_t hideSwitch = _switchHide;

    if (session) {
        remote_call_with_session(session, ^{
            ig_msg(panelWindow, @"setHidden:", 1, 0, 0, 0);
            ig_msg(hideSwitch, @"setOn:", 0, 0, 0, 0);
            ig_msg(bubbleWindow, @"setHidden:", 0, 0, 0, 0);
        });
    }
    [self setStatus:@"面板已收起 · 点左上角圆钮恢复"];
}

- (void)showPanelLocked
{
    if (!_panelHidden) return;
    _panelHidden = NO;

    RemoteCallSession *session = _session;
    uint64_t panelWindow = _panelView ? _panelView.window : 0;
    uint64_t bubbleWindow = _bubbleView ? _bubbleView.window : 0;
    uint64_t restoreSwitch = _switchRestore;

    if (session) {
        remote_call_with_session(session, ^{
            ig_msg(restoreSwitch, @"setOn:", 0, 0, 0, 0);
            ig_msg(bubbleWindow, @"setHidden:", 1, 0, 0, 0);
            ig_msg(panelWindow, @"setHidden:", 0, 0, 0, 0);
        });
    }
    _panelDirty = YES;
    [self setStatus:@"运行中"];
}

- (void)movePanelLocked
{
    [self computeLayoutLocked];

    CGRect panelRect = _panelRect;
    CGRect bubbleRect = _bubbleRect;
    uint64_t panelWindow = _panelView ? _panelView.window : 0;
    uint64_t bubbleWindow = _bubbleView ? _bubbleView.window : 0;
    RemoteCallSession *session = _session;

    if (session) {
        uint32_t previousSettle = r_settle_us(8000);
        remote_call_with_session(session, ^{
            ig_set_rect(panelWindow, "setFrame:", panelRect);
            ig_set_rect(bubbleWindow, "setFrame:", bubbleRect);
        });
        r_settle_us(previousSettle);
    }
}

#pragma mark - 画布 API

- (void)setStrips:(NSArray<NSArray<NSValue *> *> *)strips
{
    [_stripsLock lock];
    [_userStrips removeAllObjects];
    if (strips.count > 0) [_userStrips addObjectsFromArray:strips];
    [_stripsLock unlock];
    _canvasDirty = YES;
}

- (void)drawPolyline:(NSArray<NSValue *> *)points
{
    if (points.count < 2) return;
    [_stripsLock lock];
    [_userStrips addObject:[points copy]];
    if (_userStrips.count > 64) [_userStrips removeObjectAtIndex:0];
    [_stripsLock unlock];
    _canvasDirty = YES;
}

- (void)drawLineFrom:(CGPoint)from to:(CGPoint)to
{
    [self drawPolyline:@[[NSValue valueWithCGPoint:from], [NSValue valueWithCGPoint:to]]];
}

- (void)drawCircleAt:(CGPoint)center radius:(CGFloat)radius segments:(NSUInteger)segments
{
    NSUInteger count = MAX((NSUInteger)8, segments);
    NSMutableArray<NSValue *> *points = [NSMutableArray arrayWithCapacity:count + 1];
    for (NSUInteger i = 0; i <= count; i++) {
        CGFloat angle = (CGFloat)i * 2.0 * (CGFloat)M_PI / (CGFloat)count;
        [points addObject:[NSValue valueWithCGPoint:
                           CGPointMake(center.x + cos(angle) * radius,
                                       center.y + sin(angle) * radius)]];
    }
    [self drawPolyline:points];
}

- (void)clearCanvas
{
    [_stripsLock lock];
    [_userStrips removeAllObjects];
    [_stripsLock unlock];
    _canvasDirty = YES;
}

- (BOOL)demoEnabled { return _demoEnabled; }

- (void)setDemoEnabled:(BOOL)enabled
{
    _demoEnabled = enabled;
    _canvasDirty = YES;
    _panelDirty = YES;
}

- (BOOL)gridEnabled { return _gridEnabled; }

- (void)setGridEnabled:(BOOL)enabled
{
    _gridEnabled = enabled;
    _canvasDirty = YES;
    _panelDirty = YES;
}

- (CGFloat)lineWidth { return _lineWidth; }

- (void)setLineWidth:(CGFloat)width
{
    _lineWidth = MAX(0.5, MIN(12.0, width));
    _widthIndex = (NSInteger)MAX(0.0, MIN(7.0, _lineWidth - 1.0));
    _canvasDirty = YES;
    _panelDirty = YES;
}

- (UIColor *)strokeColor { return _strokeColor; }

- (void)setStrokeColor:(UIColor *)color
{
    _strokeColor = color ?: [UIColor whiteColor];
    _canvasDirty = YES;
}

@end
