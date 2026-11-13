//
//  CyanideImGuiOverlay.m
//  Cyanide
//
//  这版换掉了「整屏 PNG 推图」：
//
//  旧：每帧 CoreGraphics 画整屏 → PNG encode → remote_write 几 MB →
//      +[NSData dataWithBytes:length:] → +[UIImage imageWithData:] → setImage:
//      后三步走 r_msg2_main_raw，而那套内部每条消息就是几十次远程调用 + settle，
//      一帧 400~600ms，5 fps 都不到。
//
//  新：画线交给 SpringBoard 里的 CAShapeLayer。我们只把「点数组」写进共享页，
//      再让远程 CoreGraphics 建一条 CGPath 设给图层（见 CyanideScreenCanvas）：
//      与点数量无关，一帧 4 + 折线条数 次单条调用。
//
//      面板（ImGui 样子那块）仍然是一张图，但只渲染面板本身（252×H），
//      推图只用 3 条 objc_msgSend：dataWithBytes:length: → imageWithData: →
//      performSelectorOnMainThread:withObject:waitUntilDone:（setImage:）。
//      只有控件变化时才推。
//

#import "CyanideImGuiOverlay.h"

#import "CyanideScreenCanvas.h"
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

static const char *kIGKeyPanel = "cyanideImGuiPanelWindow";
static const char *kIGKeyBubble = "cyanideImGuiBubbleWindow";

static const CGFloat kIGPanelWidth = 252.0;
static const CGFloat kIGPanelMargin = 10.0;
static const CGFloat kIGPanelTop = 64.0;
static const CGFloat kIGBubbleSize = 38.0;
static const CGFloat kIGPanelLevel = 1000001.0;
static const CGFloat kIGRenderScale = 2.0;

static const NSTimeInterval kIGTickInterval = 1.0 / 60.0;   // 定时器节拍
static const NSTimeInterval kIGPollInterval = 0.066;        // 读控件 15Hz
static const NSTimeInterval kIGPanelPushInterval = 0.10;    // 面板最多 10Hz

static const uint32_t kIGPanelBufferBytes = 2u * 1024u * 1024u;

static const CGFloat kIGAlphaSteps[5] = {40.0, 95.0, 150.0, 205.0, 255.0};
static const NSInteger kIGFPSSteps[3] = {15, 30, 60};

#pragma mark - 远程小工具（全是单次调用）

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

static uint64_t ig_sel_c(const char *name)
{
    return ig_sel([NSString stringWithUTF8String:name]);
}

#pragma mark - 远程视图工厂

static uint64_t ig_window_create(uint64_t scene, CGRect frame)
{
    uint64_t cls = ig_class(@"UIWindow");
    if (!r_is_objc_ptr(cls)) return 0;

    uint64_t alloc = ig_msg(cls, @"alloc", 0, 0, 0, 0);
    if (!r_is_objc_ptr(alloc)) return 0;

    uint64_t window = 0;
    if (r_is_objc_ptr(scene)) {
        window = ig_msg(alloc, @"initWithWindowScene:", scene, 0, 0, 0);
        if (r_is_objc_ptr(window)) ig_set_rect(window, "setFrame:", frame);
    } else {
        alloc = ig_msg(cls, @"alloc", 0, 0, 0, 0);
        if (!r_is_objc_ptr(alloc)) return 0;
        window = r_msg2_main_raw(alloc, "initWithFrame:", &frame, sizeof(frame),
                                 NULL, 0, NULL, 0, NULL, 0);
    }
    return window;
}

static uint64_t ig_make_image_view(uint64_t parent, CGRect frame, uint64_t clear)
{
    uint64_t imageAlloc = ig_msg(ig_class(@"UIImageView"), @"alloc", 0, 0, 0, 0);
    if (!r_is_objc_ptr(imageAlloc)) return 0;

    uint64_t view = r_msg2_main_raw(imageAlloc, "initWithFrame:", &frame, sizeof(frame),
                                    NULL, 0, NULL, 0, NULL, 0);
    if (!r_is_objc_ptr(view)) return 0;

    ig_msg(view, @"setUserInteractionEnabled:", 0, 0, 0, 0);
    ig_msg(view, @"setContentMode:", 1, 0, 0, 0);   // scaleAspectFit
    if (r_is_objc_ptr(clear)) ig_msg(view, @"setBackgroundColor:", clear, 0, 0, 0);
    ig_msg(parent, @"addSubview:", view, 0, 0, 0);
    return view;
}

// 隐形控件：alpha 0.02 —— UIKit 的 hitTest 只忽略 alpha < 0.01，所以还能点。
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

    CyanideScreenCanvas *_canvas;

    uint64_t _panelWindow;
    uint64_t _bubbleWindow;
    uint64_t _imageView;
    uint64_t _bubbleImageView;

    uint64_t _switchDemo;
    uint64_t _switchGrid;
    uint64_t _switchHide;
    uint64_t _switchRestore;
    uint64_t _segWidth;
    uint64_t _segAlpha;
    uint64_t _segFPS;
    uint64_t _segAnchor;

    // 每帧要用的句柄，装好之后不再查
    uint64_t _nsdataClass;
    uint64_t _uiimageClass;
    uint64_t _selDataWithBytesLength;
    uint64_t _selImageWithData;
    uint64_t _selPerformOnMain;
    uint64_t _selSetImage;

    uint64_t _panelBuffer;
    uint32_t _panelBufferCapacity;

    BOOL _panelHidden;
    BOOL _panelDirty;
    BOOL _canvasDirty;
    BOOL _busy;

    int _panelPushFailures;
    NSTimeInterval _lastPollAt;
    NSTimeInterval _lastCanvasAt;
    NSTimeInterval _lastPanelPushAt;
    double _panelMS;
    double _canvasMS;
    double _canvasFPS;
    NSUInteger _canvasCalls;
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

        _renderScale = kIGRenderScale;
        _widthIndex = 1;                        // 线宽 2pt
        _alphaIndex = 4;                        // 不透明度 255
        _fpsIndex = 2;                          // 60fps
        _anchorIndex = 0;
        _lineWidth = (CGFloat)(_widthIndex + 1);
        _strokeColor = [UIColor colorWithRed:0.26 green:0.59 blue:0.98 alpha:1.0];
        _demoEnabled = NO;
        _gridEnabled = NO;
        _state = IGOverlayStateIdle;
        _statusLine = @"未启动";
        _canvas = [CyanideScreenCanvas sharedCanvas];
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
    _renderScale = MIN(MAX(screenScale, 1.0), kIGRenderScale);

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

    CGRect panelRect = _panelRect;
    CGRect bubbleRect = _bubbleRect;
    CGSize screenSize = _screenSize;
    BOOL demoOn = _demoEnabled;
    BOOL gridOn = _gridEnabled;
    NSInteger widthIndex = _widthIndex;
    NSInteger alphaIndex = _alphaIndex;
    NSInteger fpsIndex = _fpsIndex;
    NSInteger anchorIndex = _anchorIndex;

    __block uint64_t panelWindow = 0;
    __block uint64_t bubbleWindow = 0;
    __block uint64_t imageView = 0;
    __block uint64_t bubbleImageView = 0;
    __block uint64_t swDemo = 0, swGrid = 0, swHide = 0, swRestore = 0;
    __block uint64_t segWidth = 0, segAlpha = 0, segFPS = 0, segAnchor = 0;
    __block uint64_t scene = 0;
    __block BOOL built = NO;

    uint32_t previousSettle = r_settle_us(8000);

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
        scene = r_is_objc_ptr(keyWindow) ? ig_msg(keyWindow, @"windowScene", 0, 0, 0, 0) : 0;

        uint64_t clear = ig_msg(ig_class(@"UIColor"), @"clearColor", 0, 0, 0, 0);

        panelWindow = ig_window_create(scene, panelRect);
        if (!r_is_objc_ptr(panelWindow)) return;
        ig_set_double(panelWindow, "setWindowLevel:", (double)kIGPanelLevel);
        ig_msg(panelWindow, @"setOpaque:", 0, 0, 0, 0);
        ig_msg(panelWindow, @"setHidden:", 0, 0, 0, 0);
        if (r_is_objc_ptr(clear)) ig_msg(panelWindow, @"setBackgroundColor:", clear, 0, 0, 0);

        CGRect imageFrame = CGRectMake(0.0, 0.0, panelRect.size.width, panelRect.size.height);
        imageView = ig_make_image_view(panelWindow, imageFrame, clear);
        if (!r_is_objc_ptr(imageView)) return;

        bubbleWindow = ig_window_create(scene, bubbleRect);
        if (r_is_objc_ptr(bubbleWindow)) {
            ig_set_double(bubbleWindow, "setWindowLevel:", (double)kIGPanelLevel);
            ig_msg(bubbleWindow, @"setOpaque:", 0, 0, 0, 0);
            if (r_is_objc_ptr(clear)) ig_msg(bubbleWindow, @"setBackgroundColor:", clear, 0, 0, 0);
            ig_msg(bubbleWindow, @"setHidden:", 1, 0, 0, 0);

            CGRect bubbleImageFrame = CGRectMake(0.0, 0.0, kIGBubbleSize, kIGBubbleSize);
            bubbleImageView = ig_make_image_view(bubbleWindow, bubbleImageFrame, clear);
        }

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
        }

        uint64_t assocPanel = ig_sel_c(kIGKeyPanel);
        uint64_t assocBubble = ig_sel_c(kIGKeyBubble);
        if (assocPanel) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, assocPanel, panelWindow, 1, 0, 0, 0, 0);
        }
        if (assocBubble && r_is_objc_ptr(bubbleWindow)) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, assocBubble, bubbleWindow, 1, 0, 0, 0, 0);
        }

        built = r_is_objc_ptr(panelWindow) && r_is_objc_ptr(imageView);
        cyanide_log(@"[IMGUI] panel=0x%llx image=0x%llx bubble=0x%llx scene=0x%llx",
                    panelWindow, imageView, bubbleWindow, scene);
    });

    r_settle_us(previousSettle);

    _panelWindow = panelWindow;
    _bubbleWindow = bubbleWindow;
    _imageView = imageView;
    _bubbleImageView = bubbleImageView;
    _switchDemo = swDemo;
    _switchGrid = swGrid;
    _switchHide = swHide;
    _switchRestore = swRestore;
    _segWidth = segWidth;
    _segAlpha = segAlpha;
    _segFPS = segFPS;
    _segAnchor = segAnchor;

    if (!built) {
        [self setStatus:@"面板创建失败"];
        [self teardownLocked];
        @synchronized (self) { _state = IGOverlayStateFailed; }
        return;
    }

    // 画布：全屏透明、点击穿透，线走 CAShapeLayer
    if (![_canvas attachWithSession:session scene:scene screenSize:screenSize]) {
        [self setStatus:@"画布创建失败"];
        [self teardownLocked];
        @synchronized (self) { _state = IGOverlayStateFailed; }
        return;
    }
    [_canvas setGridVisible:gridOn];

    // 每帧要用的句柄，先查好（之后每帧只发 r_msg）
    _nsdataClass = ig_class(@"NSData");
    _uiimageClass = ig_class(@"UIImage");
    _selDataWithBytesLength = ig_sel(@"dataWithBytes:length:");
    _selImageWithData = ig_sel(@"imageWithData:");
    _selPerformOnMain = ig_sel(@"performSelectorOnMainThread:withObject:waitUntilDone:");
    _selSetImage = ig_sel(@"setImage:");

    [self ensurePanelBufferLocked];

    if (r_is_objc_ptr(_bubbleImageView)) {
        NSData *bubblePNG = [self renderBubblePNGLocked];
        if (bubblePNG.length > 0) [self pushPNGLocked:bubblePNG toImageView:_bubbleImageView];
    }

    [self pushPanelLocked];
    [self updateCanvasLocked];

    [self startTimerLocked];
    [self setStatus:[NSString stringWithFormat:@"运行中 · %.0f×%.0f", _screenSize.width, _screenSize.height]];
    @synchronized (self) { _state = IGOverlayStateRunning; }
    cyanide_log(@"[IMGUI] running");
}

- (void)teardownLocked
{
    if (_timer) {
        dispatch_source_cancel(_timer);
        _timer = nil;
    }

    [_canvas detach];

    RemoteCallSession *session = _session;
    uint64_t panelWindow = _panelWindow;
    uint64_t bubbleWindow = _bubbleWindow;
    uint64_t panelBuffer = _panelBuffer;

    if (session) {
        uint32_t previousSettle = r_settle_us(8000);
        remote_call_with_session(session, ^{
            if (r_is_objc_ptr(panelWindow)) ig_msg(panelWindow, @"setHidden:", 1, 0, 0, 0);
            if (r_is_objc_ptr(bubbleWindow)) ig_msg(bubbleWindow, @"setHidden:", 1, 0, 0, 0);

            uint64_t app = ig_msg(ig_class(@"UIApplication"), @"sharedApplication", 0, 0, 0, 0);
            if (r_is_objc_ptr(app)) {
                uint64_t assocPanel = ig_sel_c(kIGKeyPanel);
                uint64_t assocBubble = ig_sel_c(kIGKeyBubble);
                if (assocPanel) {
                    r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, assocPanel, 0, 1, 0, 0, 0, 0);
                }
                if (assocBubble) {
                    r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, assocBubble, 0, 1, 0, 0, 0, 0);
                }
            }
            if (r_is_objc_ptr(panelBuffer)) {
                r_dlsym_call(R_TIMEOUT, "free", panelBuffer, 0, 0, 0, 0, 0, 0, 0);
            }
        });
        r_settle_us(previousSettle);
    }

    _panelWindow = 0;
    _bubbleWindow = 0;
    _imageView = 0;
    _bubbleImageView = 0;
    _switchDemo = 0;
    _switchGrid = 0;
    _switchHide = 0;
    _switchRestore = 0;
    _segWidth = 0;
    _segAlpha = 0;
    _segFPS = 0;
    _segAnchor = 0;
    _panelBuffer = 0;
    _panelBufferCapacity = 0;
    _panelHidden = NO;
    _panelDirty = NO;
    _canvasDirty = NO;
    _panelPushFailures = 0;
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

    [ui text:[NSString stringWithFormat:@"canvas %.0f fps · %lu calls",
              _canvasFPS, (unsigned long)_canvasCalls]];
    [ui textDisabled:[NSString stringWithFormat:@"canvas %.1fms  panel %.1fms",
                      _canvasMS, _panelMS]];
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
            [self updateCanvasLocked];
        }

        if (_panelDirty && !_panelHidden && (now - _lastPanelPushAt) >= kIGPanelPushInterval) {
            _lastPanelPushAt = now;
            _panelDirty = NO;
            [self pushPanelLocked];
        }
    } @finally {
        _busy = NO;
    }
}

#pragma mark - 画布

- (NSArray<NSArray<NSValue *> *> *)demoStripsLocked
{
    CGSize size = _screenSize;
    CGPoint center = CGPointMake(size.width / 2.0, size.height / 2.0);
    CGFloat radius = MIN(size.width, size.height) * 0.30;

    // 八根辐条拼成一条折线：每根都从圆心出发，不会有跨辐条的多余连线
    NSMutableArray<NSValue *> *spokes = [NSMutableArray arrayWithCapacity:18];
    for (NSInteger i = 0; i <= 8; i++) {
        CGFloat angle = (CGFloat)_demoPhase + (CGFloat)i * (CGFloat)M_PI / 4.0;
        [spokes addObject:[NSValue valueWithCGPoint:center]];
        [spokes addObject:[NSValue valueWithCGPoint:
                           CGPointMake(center.x + cos(angle) * radius,
                                       center.y + sin(angle) * radius)]];
    }

    // 呼吸圆环：48 边形闭合折线
    CGFloat ringRadius = 42.0 + 9.0 * (CGFloat)sin(_demoPhase * 2.0);
    NSMutableArray<NSValue *> *ring = [NSMutableArray arrayWithCapacity:49];
    for (NSInteger i = 0; i <= 48; i++) {
        CGFloat angle = (CGFloat)i * 2.0 * (CGFloat)M_PI / 48.0;
        [ring addObject:[NSValue valueWithCGPoint:
                         CGPointMake(center.x + cos(angle) * ringRadius,
                                     center.y + sin(angle) * ringRadius)]];
    }

    return @[spokes, ring];
}

- (void)updateCanvasLocked
{
    NSMutableArray<NSArray<NSValue *> *> *strips = [NSMutableArray array];

    if (_demoEnabled) [strips addObjectsFromArray:[self demoStripsLocked]];

    [_stripsLock lock];
    if (_userStrips.count > 0) [strips addObjectsFromArray:_userStrips];
    [_stripsLock unlock];

    UIColor *color = [_strokeColor colorWithAlphaComponent:kIGAlphaSteps[_alphaIndex] / 255.0];
    [_canvas setStrips:strips color:color width:_lineWidth];

    _canvasCalls = _canvas.lastCallCount;
    _canvasMS = _canvas.lastUpdateMS;
    if (_canvasMS > 0.05) {
        double instant = 1000.0 / _canvasMS;
        _canvasFPS = (_canvasFPS < 1.0) ? instant : (_canvasFPS * 0.8 + instant * 0.2);
    }
}

#pragma mark - 面板推图

- (void)ensurePanelBufferLocked
{
    if (r_is_objc_ptr(_panelBuffer) && _panelBufferCapacity >= kIGPanelBufferBytes) return;
    if (!_session) return;

    RemoteCallSession *session = _session;
    __block uint64_t buffer = 0;
    remote_call_with_session(session, ^{
        buffer = r_dlsym_call(R_TIMEOUT, "malloc", kIGPanelBufferBytes, 0, 0, 0, 0, 0, 0, 0);
    });

    if (r_is_objc_ptr(buffer)) {
        _panelBuffer = buffer;
        _panelBufferCapacity = kIGPanelBufferBytes;
    } else {
        cyanide_log(@"[IMGUI] panel buffer alloc failed");
    }
}

- (NSData *)renderPanelPNGLocked
{
    [_ui beginFrameWithDisplaySize:_screenSize];
    [_ui beginWindow:@"Cyanide · ImGui" frame:_panelRect];
    [self buildPanelRowsWithCapture:nil];
    [_ui endWindow];
    [_ui endFrame];

    UIImage *image = [_ui.drawList renderWithSize:_panelRect.size
                                            scale:_renderScale
                                        translate:IGVec2Make(_panelRect.origin.x,
                                                             _panelRect.origin.y)];
    return image ? UIImagePNGRepresentation(image) : nil;
}

- (NSData *)renderBubblePNGLocked
{
    IGDrawList *list = [[IGDrawList alloc] init];
    CGFloat half = kIGBubbleSize / 2.0;
    [list addCircleFilledAt:IGVec2Make(half, half)
                     radius:half - 1.0
                      color:IGColorMake(0.06, 0.06, 0.06, 0.92)];
    [list addCircleAt:IGVec2Make(half, half)
               radius:half - 1.0
                color:IGColorMake(0.26, 0.59, 0.98, 0.90)
            thickness:1.5];
    [list addText:@"IG"
               at:IGVec2Make(half - 8.0, half - 7.0)
         fontSize:12.0
            color:IGColorMake(1.0, 1.0, 1.0, 0.95)];
    UIImage *image = [list renderWithSize:CGSizeMake(kIGBubbleSize, kIGBubbleSize)
                                   scale:_renderScale];
    return image ? UIImagePNGRepresentation(image) : nil;
}

// 3 条消息：dataWithBytes:length: → imageWithData: → 主线程 setImage:
- (BOOL)pushPNGLocked:(NSData *)png toImageView:(uint64_t)imageView
{
    if (!_session || !r_is_objc_ptr(imageView) || png.length == 0) return NO;
    if (!r_is_objc_ptr(_panelBuffer)) [self ensurePanelBufferLocked];
    if (!r_is_objc_ptr(_panelBuffer) || png.length > _panelBufferCapacity) return NO;

    RemoteCallSession *session = _session;
    uint64_t buffer = _panelBuffer;
    const void *bytes = png.bytes;
    uint64_t length = (uint64_t)png.length;
    uint64_t nsdataClass = _nsdataClass;
    uint64_t uiimageClass = _uiimageClass;
    uint64_t selData = _selDataWithBytesLength;
    uint64_t selImage = _selImageWithData;
    uint64_t selPerform = _selPerformOnMain;
    uint64_t selSetImage = _selSetImage;

    __block BOOL ok = NO;
    remote_call_with_session(session, ^{
        if (!remote_write(buffer, bytes, length)) {
            cyanide_log(@"[IMGUI] remote_write failed (%llu bytes)", length);
            return;
        }

        uint64_t data = r_msg(nsdataClass, selData, buffer, length, 0, 0);
        if (!r_is_objc_ptr(data)) return;

        uint64_t image = r_msg(uiimageClass, selImage, data, 0, 0, 0);
        if (!r_is_objc_ptr(image)) return;

        r_msg(imageView, selPerform, selSetImage, image, 1, 0);
        ok = YES;
    });
    return ok;
}

- (void)pushPanelLocked
{
    if (!_session || !r_is_objc_ptr(_imageView)) return;

    NSTimeInterval begin = CACurrentMediaTime();
    NSData *png = [self renderPanelPNGLocked];
    if (png.length == 0) return;
    if (png.length > _panelBufferCapacity) {
        cyanide_log(@"[IMGUI] panel png too big: %lu", (unsigned long)png.length);
        return;
    }

    BOOL ok = [self pushPNGLocked:png toImageView:_imageView];
    _panelMS = (CACurrentMediaTime() - begin) * 1000.0;

    if (ok) {
        _panelPushFailures = 0;
    } else {
        _panelPushFailures += 1;
        cyanide_log(@"[IMGUI] panel push failed (%d)", _panelPushFailures);
        if (_panelPushFailures >= 5) [self setStatus:@"面板推图连续失败"];
    }
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
        [_canvas setGridVisible:grid];
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
    uint64_t panelWindow = _panelWindow;
    uint64_t hideSwitch = _switchHide;
    uint64_t bubbleWindow = _bubbleWindow;

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
    uint64_t panelWindow = _panelWindow;
    uint64_t restoreSwitch = _switchRestore;
    uint64_t bubbleWindow = _bubbleWindow;

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

    RemoteCallSession *session = _session;
    uint64_t panelWindow = _panelWindow;
    uint64_t bubbleWindow = _bubbleWindow;

    if (session) {
        uint32_t previousSettle = r_settle_us(8000);
        remote_call_with_session(session, ^{
            ig_set_rect(panelWindow, "setFrame:", panelRect);
            ig_set_rect(bubbleWindow, "setFrame:", bubbleRect);
        });
        r_settle_us(previousSettle);
    }
    _panelDirty = YES;
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
    [_canvas clear];
    _canvasDirty = NO;
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
    [_canvas setGridVisible:enabled];
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
