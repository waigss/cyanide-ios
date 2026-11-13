//
//  CyanideScreenCanvas.m
//  Cyanide
//

#import "CyanideScreenCanvas.h"

#import "../TaskRop/RemoteCall.h"
#import "../tweaks/remote_objc.h"
#import "CyanideLog.h"

#import <QuartzCore/QuartzCore.h>
#import <math.h>
#import <string.h>

// 一帧最多这么多点（16 字节一个点 = 256KB 缓冲区）。
static const NSUInteger kCvMaxPoints = 16384;
static const NSUInteger kCvPointStride = 16;   // sizeof(CGPoint) on 64-bit
static const uint32_t kCvPointBufferBytes = 256u * 1024u;

static const CGFloat kCvWindowLevel = 1000000.0;

#pragma mark - 远程小工具

// 全是「一次远程调用」的原语：r_msg / r_dlsym_call 内部只做一次线程劫持，
// 不建 NSInvocation，也不 sleep。r_msg2* 那套每条消息内部有几十次调用 + settle，
// 帧循环里绝对不能用。

static NSMutableDictionary<NSString *, NSNumber *> *gCvSelectorCache = nil;

static uint64_t cv_sel(NSString *name)
{
    if (!name) return 0;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gCvSelectorCache = [NSMutableDictionary dictionaryWithCapacity:64];
    });
    NSNumber *cached = gCvSelectorCache[name];
    if (cached) return cached.unsignedLongLongValue;

    uint64_t sel = r_sel(name.UTF8String);
    if (sel) gCvSelectorCache[name] = @(sel);
    return sel;
}

static uint64_t cv_msg(uint64_t obj, NSString *selName, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!r_is_objc_ptr(obj)) return 0;
    uint64_t sel = cv_sel(selName);
    if (!sel) return 0;
    return r_msg(obj, sel, a0, a1, a2, a3);
}

static uint64_t cv_dlsym(const char *name, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!name) return 0;
    return r_dlsym_call(R_TIMEOUT, name, a0, a1, a2, a3, 0, 0, 0, 0);
}

// 下面几个只用于「装好之后就不再变」的属性，走 NSInvocation 拿浮点/结构体实参：
// setWindowLevel: / setFrame: / setLineWidth: / colorWithRed:green:blue:alpha:
static void cv_set_double(uint64_t obj, const char *selName, double value)
{
    if (!r_is_objc_ptr(obj) || !selName) return;
    r_msg2_main_raw(obj, selName, &value, sizeof(value), NULL, 0, NULL, 0, NULL, 0);
}

static void cv_set_rect(uint64_t obj, const char *selName, CGRect rect)
{
    if (!r_is_objc_ptr(obj) || !selName) return;
    r_msg2_main_raw(obj, selName, &rect, sizeof(rect), NULL, 0, NULL, 0, NULL, 0);
}

static uint64_t cv_make_color(CGFloat r, CGFloat g, CGFloat b, CGFloat a)
{
    double rgba[4] = { (double)r, (double)g, (double)b, (double)a };
    uint64_t cls = r_class("UIColor");
    if (!r_is_objc_ptr(cls)) return 0;
    return r_msg2_main_raw(cls, "colorWithRed:green:blue:alpha:",
                           &rgba[0], sizeof(double),
                           &rgba[1], sizeof(double),
                           &rgba[2], sizeof(double),
                           &rgba[3], sizeof(double));
}

static uint64_t cv_cgpath_new(void)
{
    return cv_dlsym("CGPathCreateMutable", 0, 0, 0, 0);
}

static void cv_cgpath_add_lines(uint64_t path, uint64_t points, uint64_t count)
{
    if (!r_is_objc_ptr(path) || !r_is_objc_ptr(points) || count < 2) return;
    cv_dlsym("CGPathAddLines", path, 0, points, count);
}

static void cv_cgpath_add_path(uint64_t dst, uint64_t src)
{
    if (!r_is_objc_ptr(dst) || !r_is_objc_ptr(src)) return;
    cv_dlsym("CGPathAddPath", dst, 0, src, 0);
}

static void cv_cgpath_release(uint64_t path)
{
    if (!r_is_objc_ptr(path)) return;
    cv_dlsym("CGPathRelease", path, 0, 0, 0);
}

// 我们是在被劫持的 SpringBoard 线程上改 layer.path 的：改动会落在线程本地事务里，
// 必须显式提交才会送到渲染服务器。CATransactionCommit 是 0 参公开 API，一次调用。
static void cv_commit(void)
{
    cv_dlsym("CATransactionCommit", 0, 0, 0, 0);
}

#pragma mark - 画布

@implementation CyanideScreenCanvas {
    RemoteCallSession *_session;
    CGSize _screenSize;

    uint64_t _window;
    uint64_t _hostLayer;
    uint64_t _lineLayer;
    uint64_t _gridLayer;

    uint64_t _path;          // 当前动态图层持有的 CGPath（我们持有一份 +1）
    uint64_t _gridPath;
    BOOL _gridBuilt;

    uint64_t _pointBuffer;
    uint32_t _pointCapacity;

    uint64_t _strokeColor;   // 远程 CGColorRef，变了才重设
    CGFloat _strokeWidth;
    CGFloat _strokeR, _strokeG, _strokeB, _strokeA;

    NSUInteger _lastCallCount;
    double _lastUpdateMS;
}

+ (instancetype)sharedCanvas
{
    static CyanideScreenCanvas *shared = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        shared = [[CyanideScreenCanvas alloc] init];
    });
    return shared;
}

- (BOOL)attached
{
    return r_is_objc_ptr(_window) && r_is_objc_ptr(_lineLayer);
}

- (NSUInteger)lastCallCount
{
    return _lastCallCount;
}

- (double)lastUpdateMS
{
    return _lastUpdateMS;
}

#pragma mark 挂载

- (BOOL)attachWithSession:(RemoteCallSession *)session scene:(uint64_t)scene screenSize:(CGSize)screenSize
{
    if (!session) return NO;
    if (self.attached) return YES;

    _session = session;
    _screenSize = screenSize;

    CGRect screenRect = CGRectMake(0.0, 0.0, screenSize.width, screenSize.height);
    BOOL hasScene = (scene != 0);

    // 装窗口只做一次，走 NSInvocation 的几次调用再慢也无所谓；把 settle 压到 8ms
    // 让这几条别各等 50ms。
    uint32_t previousSettle = r_settle_us(8000);

    __block uint64_t window = 0;
    __block uint64_t hostLayer = 0;
    __block uint64_t lineLayer = 0;
    __block uint64_t gridLayer = 0;
    __block BOOL ok = NO;

    remote_call_with_session(session, ^{
        uint64_t windowClass = r_class("UIWindow");
        if (!r_is_objc_ptr(windowClass)) return;

        uint64_t alloc = cv_msg(windowClass, @"alloc", 0, 0, 0, 0);
        if (!r_is_objc_ptr(alloc)) return;

        if (hasScene) {
            window = cv_msg(alloc, @"initWithWindowScene:", scene, 0, 0, 0);
        } else {
            alloc = cv_msg(windowClass, @"alloc", 0, 0, 0, 0);
            if (!r_is_objc_ptr(alloc)) return;
            window = r_msg2_main_raw(alloc, "initWithFrame:", &screenRect, sizeof(screenRect),
                                     NULL, 0, NULL, 0, NULL, 0);
        }
        if (!r_is_objc_ptr(window)) return;

        cv_set_double(window, "setWindowLevel:", (double)kCvWindowLevel);
        cv_msg(window, @"setOpaque:", 0, 0, 0, 0);
        cv_msg(window, @"setUserInteractionEnabled:", 0, 0, 0, 0);   // ← 点击穿透
        cv_msg(window, @"setHidden:", 0, 0, 0, 0);

        uint64_t clearColor = cv_msg(r_class("UIColor"), @"clearColor", 0, 0, 0, 0);
        if (r_is_objc_ptr(clearColor)) cv_msg(window, @"setBackgroundColor:", clearColor, 0, 0, 0);

        hostLayer = cv_msg(window, @"layer", 0, 0, 0, 0);
        if (!r_is_objc_ptr(hostLayer)) return;

        uint64_t layerClass = r_class("CAShapeLayer");
        if (!r_is_objc_ptr(layerClass)) return;

        lineLayer = cv_msg(layerClass, @"layer", 0, 0, 0, 0);
        if (!r_is_objc_ptr(lineLayer)) return;

        cv_set_rect(lineLayer, "setFrame:", screenRect);
        cv_msg(lineLayer, @"setFillColor:", 0, 0, 0, 0);      // 只描边
        cv_msg(lineLayer, @"setLineCap:", 1, 0, 0, 0);        // kCALineCapRound
        cv_msg(lineLayer, @"setLineJoin:", 1, 0, 0, 0);       // kCALineJoinRound
        cv_msg(hostLayer, @"addSublayer:", lineLayer, 0, 0, 0);

        gridLayer = cv_msg(layerClass, @"layer", 0, 0, 0, 0);
        if (r_is_objc_ptr(gridLayer)) {
            cv_set_rect(gridLayer, "setFrame:", screenRect);
            cv_msg(gridLayer, @"setFillColor:", 0, 0, 0, 0);
            cv_set_double(gridLayer, "setLineWidth:", 0.5);
            cv_msg(gridLayer, @"setHidden:", 1, 0, 0, 0);
            cv_msg(hostLayer, @"addSublayer:", gridLayer, 0, 0, 0);
        }

        // 关联到 UIApplication，避免窗口被别处释放。
        uint64_t app = cv_msg(r_class("UIApplication"), @"sharedApplication", 0, 0, 0, 0);
        uint64_t key = cv_sel(@"cyanideScreenCanvasWindow");
        if (r_is_objc_ptr(app) && key) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, key, window, 1, 0, 0, 0, 0);
        }

        ok = r_is_objc_ptr(window) && r_is_objc_ptr(lineLayer);
        cv_commit();
    });

    r_settle_us(previousSettle);

    if (!ok) {
        cyanide_log(@"[CANVAS] attach failed");
        return NO;
    }

    _window = window;
    _hostLayer = hostLayer;
    _lineLayer = lineLayer;
    _gridLayer = gridLayer;
    _strokeWidth = 0.0;

    cyanide_log(@"[CANVAS] attached window=0x%llx line=0x%llx grid=0x%llx",
                window, lineLayer, gridLayer);
    return YES;
}

- (void)detach
{
    if (!r_is_objc_ptr(_window) || !_session) {
        _window = 0;
        _lineLayer = 0;
        _gridLayer = 0;
        return;
    }

    RemoteCallSession *session = _session;
    uint64_t window = _window;
    uint64_t lineLayer = _lineLayer;
    uint64_t gridLayer = _gridLayer;
    uint64_t path = _path;
    uint64_t gridPath = _gridPath;
    uint64_t buffer = _pointBuffer;

    uint32_t previousSettle = r_settle_us(8000);
    remote_call_with_session(session, ^{
        if (r_is_objc_ptr(window)) {
            cv_msg(window, @"setHidden:", 1, 0, 0, 0);
            cv_msg(window, @"setUserInteractionEnabled:", 0, 0, 0, 0);
        }
        if (r_is_objc_ptr(lineLayer)) cv_msg(lineLayer, @"setPath:", 0, 0, 0, 0);
        if (r_is_objc_ptr(gridLayer)) cv_msg(gridLayer, @"setPath:", 0, 0, 0, 0);
        cv_cgpath_release(path);
        cv_cgpath_release(gridPath);
        if (r_is_objc_ptr(buffer)) cv_dlsym("free", buffer, 0, 0, 0);

        uint64_t app = cv_msg(r_class("UIApplication"), @"sharedApplication", 0, 0, 0, 0);
        uint64_t key = cv_sel(@"cyanideScreenCanvasWindow");
        if (r_is_objc_ptr(app) && key) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, key, 0, 1, 0, 0, 0, 0);
        }
        cv_commit();
    });
    r_settle_us(previousSettle);

    _window = 0;
    _hostLayer = 0;
    _lineLayer = 0;
    _gridLayer = 0;
    _path = 0;
    _gridPath = 0;
    _pointBuffer = 0;
    _pointCapacity = 0;
    _gridBuilt = NO;
    _strokeColor = 0;
    _strokeWidth = 0.0;
    _session = nil;
    cyanide_log(@"[CANVAS] detached");
}

#pragma mark 缓冲区

- (BOOL)ensurePointBufferLocked:(NSUInteger)bytes
{
    if (bytes > kCvPointBufferBytes) return NO;
    if (r_is_objc_ptr(_pointBuffer) && _pointCapacity >= bytes) return YES;
    if (!_session) return NO;

    RemoteCallSession *session = _session;
    uint64_t oldBuffer = _pointBuffer;
    __block uint64_t buffer = 0;

    remote_call_with_session(session, ^{
        buffer = cv_dlsym("malloc", kCvPointBufferBytes, 0, 0, 0);
        if (r_is_objc_ptr(buffer) && r_is_objc_ptr(oldBuffer)) {
            cv_dlsym("free", oldBuffer, 0, 0, 0);
        }
    });

    if (!r_is_objc_ptr(buffer)) {
        cyanide_log(@"[CANVAS] point buffer alloc failed");
        return NO;
    }
    _pointBuffer = buffer;
    _pointCapacity = kCvPointBufferBytes;
    return YES;
}

#pragma mark 颜色 / 线宽

// 这些属性只在值变化时下发：一次 setStrokeColor: 是 1 条消息，建 CGColor 是
// 一次 NSInvocation。帧循环里重复设同一个值纯属浪费。
- (void)applyStrokeColorLocked:(UIColor *)color
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
    if (fabs(r - _strokeR) < 0.002 && fabs(g - _strokeG) < 0.002 &&
        fabs(b - _strokeB) < 0.002 && fabs(a - _strokeA) < 0.002 &&
        r_is_objc_ptr(_strokeColor)) {
        return;
    }

    uint64_t uiColor = cv_make_color(r, g, b, a);
    if (!r_is_objc_ptr(uiColor)) return;

    uint64_t cgColor = cv_msg(uiColor, @"CGColor", 0, 0, 0, 0);
    if (!r_is_objc_ptr(cgColor)) return;

    cv_msg(_lineLayer, @"setStrokeColor:", cgColor, 0, 0, 0);
    cv_commit();

    _strokeColor = cgColor;
    _strokeR = r;
    _strokeG = g;
    _strokeB = b;
    _strokeA = a;
}

- (void)applyLineWidthLocked:(CGFloat)width
{
    if (fabs(width - _strokeWidth) < 0.01 && _strokeWidth > 0.0) return;
    cv_set_double(_lineLayer, "setLineWidth:", (double)width);
    _strokeWidth = width;
}

#pragma mark 画线

- (void)setStrips:(NSArray<NSArray<NSValue *> *> *)strips
            color:(UIColor *)color
            width:(CGFloat)width
{
    if (!self.attached || !_session) return;

    NSTimeInterval begin = CACurrentMediaTime();

    NSMutableData *points = [NSMutableData data];
    NSMutableArray<NSNumber *> *layout = [NSMutableArray array];   // 偶数=起点下标，奇数=点数
    NSUInteger total = 0;

    for (NSArray<NSValue *> *strip in strips) {
        if (strip.count < 2) continue;
        if (total + strip.count > kCvMaxPoints) break;
        [layout addObject:@(total)];
        [layout addObject:@(strip.count)];
        for (NSValue *value in strip) {
            CGPoint point = value.CGPointValue;
            [points appendBytes:&point length:sizeof(point)];
        }
        total += strip.count;
    }

    if (total < 2) {
        [self clear];
        return;
    }
    if (![self ensurePointBufferLocked:points.length]) return;

    [self applyStrokeColorLocked:color ?: [UIColor whiteColor]];
    [self applyLineWidthLocked:width];

    RemoteCallSession *session = _session;
    uint64_t buffer = _pointBuffer;
    uint64_t layer = _lineLayer;
    uint64_t oldPath = _path;
    const void *bytes = points.bytes;
    uint64_t length = (uint64_t)points.length;
    NSUInteger stripCount = layout.count / 2;
    NSUInteger pointCount = total;
    NSArray<NSNumber *> *layoutCopy = [layout copy];

    __block uint64_t newPath = 0;
    __block NSUInteger calls = 0;

    remote_call_with_session(session, ^{
        if (!remote_write(buffer, bytes, length)) {
            cyanide_log(@"[CANVAS] remote_write failed (%llu bytes)", length);
            return;
        }
        calls += 1;

        uint64_t path = cv_cgpath_new();
        calls += 1;
        if (!r_is_objc_ptr(path)) return;

        if (stripCount <= 1) {
            cv_cgpath_add_lines(path, buffer, (uint64_t)pointCount);
            calls += 1;
        } else {
            // 每条折线单独建一条 path 再 append 进来。CGPathAddLines 在非空 path 上
            // 会接在当前点后面画，连着调几条折线会被串成一条。
            for (NSUInteger i = 0; i < stripCount; i++) {
                uint64_t offset = layoutCopy[i * 2].unsignedLongLongValue;
                uint64_t count = layoutCopy[i * 2 + 1].unsignedLongLongValue;
                uint64_t strip = cv_cgpath_new();
                calls += 1;
                if (!r_is_objc_ptr(strip)) continue;
                cv_cgpath_add_lines(strip, buffer + offset * kCvPointStride, count);
                cv_cgpath_add_path(path, strip);
                cv_cgpath_release(strip);
                calls += 3;
            }
        }

        cv_msg(layer, @"setPath:", path, 0, 0, 0);
        calls += 1;

        // 上一帧的 path 只有我们还持有一份引用
        cv_cgpath_release(oldPath);
        calls += 1;

        cv_commit();
        calls += 1;

        newPath = path;
    });

    if (r_is_objc_ptr(newPath)) _path = newPath;

    _lastCallCount = calls;
    _lastUpdateMS = (CACurrentMediaTime() - begin) * 1000.0;
}

- (void)clear
{
    if (!self.attached || !_session) return;

    RemoteCallSession *session = _session;
    uint64_t layer = _lineLayer;
    uint64_t oldPath = _path;

    __block NSUInteger calls = 0;
    remote_call_with_session(session, ^{
        uint64_t path = cv_cgpath_new();
        calls += 1;
        if (r_is_objc_ptr(path)) {
            cv_msg(layer, @"setPath:", path, 0, 0, 0);
            calls += 2;
        } else {
            cv_msg(layer, @"setPath:", 0, 0, 0, 0);
            calls += 1;
        }
        cv_cgpath_release(oldPath);
        calls += 1;
        cv_commit();
        calls += 1;
    });

    _path = 0;
    _lastCallCount = calls;
}

#pragma mark 网格

- (void)buildGridLocked
{
    if (_gridBuilt || !self.attached || !_session || !r_is_objc_ptr(_gridLayer)) return;

    NSMutableData *points = [NSMutableData data];
    NSMutableArray<NSNumber *> *layout = [NSMutableArray array];
    NSUInteger total = 0;
    CGFloat step = 64.0;

    for (CGFloat x = 0.0; x <= _screenSize.width && total + 2 <= kCvMaxPoints; x += step) {
        CGPoint pair[2] = { CGPointMake(x, 0.0), CGPointMake(x, _screenSize.height) };
        [layout addObject:@(total)];
        [layout addObject:@(2)];
        [points appendBytes:pair length:sizeof(pair)];
        total += 2;
    }
    for (CGFloat y = 0.0; y <= _screenSize.height && total + 2 <= kCvMaxPoints; y += step) {
        CGPoint pair[2] = { CGPointMake(0.0, y), CGPointMake(_screenSize.width, y) };
        [layout addObject:@(total)];
        [layout addObject:@(2)];
        [points appendBytes:pair length:sizeof(pair)];
        total += 2;
    }
    if (total < 2) return;
    if (![self ensurePointBufferLocked:points.length]) return;

    RemoteCallSession *session = _session;
    uint64_t buffer = _pointBuffer;
    uint64_t layer = _gridLayer;
    const void *bytes = points.bytes;
    uint64_t length = (uint64_t)points.length;
    NSUInteger stripCount = layout.count / 2;
    NSArray<NSNumber *> *layoutCopy = [layout copy];

    __block uint64_t path = 0;
    uint32_t previousSettle = r_settle_us(8000);
    remote_call_with_session(session, ^{
        remote_write(buffer, bytes, length);

        uint64_t gridPath = cv_cgpath_new();
        if (!r_is_objc_ptr(gridPath)) return;

        for (NSUInteger i = 0; i < stripCount; i++) {
            uint64_t offset = layoutCopy[i * 2].unsignedLongLongValue;
            uint64_t count = layoutCopy[i * 2 + 1].unsignedLongLongValue;
            uint64_t strip = cv_cgpath_new();
            if (!r_is_objc_ptr(strip)) continue;
            cv_cgpath_add_lines(strip, buffer + offset * kCvPointStride, count);
            cv_cgpath_add_path(gridPath, strip);
            cv_cgpath_release(strip);
        }

        // 网格自己一套暗色，不跟着画笔颜色变
        uint64_t uiColor = cv_make_color(1.0, 1.0, 1.0, 0.16);
        if (r_is_objc_ptr(uiColor)) {
            uint64_t cgColor = cv_msg(uiColor, @"CGColor", 0, 0, 0, 0);
            if (r_is_objc_ptr(cgColor)) cv_msg(layer, @"setStrokeColor:", cgColor, 0, 0, 0);
        }
        cv_set_double(layer, "setLineWidth:", 0.5);

        cv_msg(layer, @"setPath:", gridPath, 0, 0, 0);
        path = gridPath;
        cv_commit();
    });
    r_settle_us(previousSettle);

    if (r_is_objc_ptr(path)) {
        cv_cgpath_release(_gridPath);
        _gridPath = path;
        _gridBuilt = YES;
        cyanide_log(@"[CANVAS] grid built strips=%lu", (unsigned long)stripCount);
    }
}

- (void)setGridVisible:(BOOL)visible
{
    if (!self.attached || !_session || !r_is_objc_ptr(_gridLayer)) return;

    if (visible && !_gridBuilt) {
        [self buildGridLocked];
    }

    RemoteCallSession *session = _session;
    uint64_t layer = _gridLayer;
    uint64_t hidden = visible ? 0 : 1;

    remote_call_with_session(session, ^{
        cv_msg(layer, @"setHidden:", hidden, 0, 0, 0);
        cv_commit();
    });
}

@end
