//
//  CyanidePixelView.m
//  Cyanide
//

#import "CyanidePixelView.h"

#import "../TaskRop/RemoteCall.h"
#import "../tweaks/remote_objc.h"
#import "CyanideLog.h"

#import <QuartzCore/QuartzCore.h>
#import <stdlib.h>
#import <string.h>

static NSMutableDictionary<NSString *, NSNumber *> *gPxSelectorCache = nil;
static NSUInteger gPxAssocSeed = 0;   // 每块视图一个独立的关联 key

static uint64_t px_sel(NSString *name)
{
    if (!name) return 0;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gPxSelectorCache = [NSMutableDictionary dictionaryWithCapacity:32];
    });
    NSNumber *cached = gPxSelectorCache[name];
    if (cached) return cached.unsignedLongLongValue;
    uint64_t sel = r_sel(name.UTF8String);
    if (sel) gPxSelectorCache[name] = @(sel);
    return sel;
}

// 建窗口/加子视图/设 hidden 全部必须在 SpringBoard 主线程上做：UIWindow 在非主线程
// 创建不会进入显示链，窗口就永远不出现。r_msg2_main 走
// performSelectorOnMainThread:waitUntilDone:YES，是同步的。
// 每帧的 setImage: 不用它，用单次 performSelectorOnMainThread:（见 blitWithScale:）。
static uint64_t px_msg(uint64_t obj, NSString *selName, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!r_is_objc_ptr(obj) || !selName) return 0;
    return r_msg2_main(obj, selName.UTF8String, a0, a1, a2, a3);
}

// 位图格式：BGRA little-endian + premultiplied first，和 UIGraphicsImageRenderer
// 的默认输出一致，也和后面远程 CGBitmapContext 用的旗标一致。
static uint32_t px_bitmap_info(void)
{
    return (uint32_t)(kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
}

@implementation CyanidePixelView {
    RemoteCallSession *_session;
    uint64_t _window;
    uint64_t _imageView;

    uint64_t _pixelBuffer;      // 远程 malloc 的像素内存
    uint64_t _context;          // 远程 CGBitmapContext（数据指向 _pixelBuffer）
    uint64_t _lastImage;        // 上一帧的 CGImage，我们持有 +1
    uint64_t _assocKey;         // 关联到 UIApplication 的 key（每块视图不同）
    uint32_t _pixelBufferBytes;

    CGSize _pixelSize;
    void *_localPixels;
    CGContextRef _localContext;

    uint64_t _imageClass;
    uint64_t _selAlloc;
    uint64_t _selInitWithCGImage;
    uint64_t _selPerformOnMain;
    uint64_t _selSetImage;
    uint64_t _selRelease;

    BOOL _ready;
    NSUInteger _lastCallCount;
    double _lastUpdateMS;
}

+ (instancetype)viewWithSession:(RemoteCallSession *)session
                          scene:(uint64_t)scene
                          frame:(CGRect)frame
                          level:(CGFloat)level
                          scale:(CGFloat)scale
{
    CyanidePixelView *view = [[CyanidePixelView alloc] init];
    if (![view setupWithSession:session scene:scene frame:frame level:level scale:scale]) return nil;
    return view;
}

- (BOOL)setupWithSession:(RemoteCallSession *)session
                   scene:(uint64_t)scene
                   frame:(CGRect)frame
                   level:(CGFloat)level
                   scale:(CGFloat)scale
{
    if (!session) return NO;
    if (frame.size.width < 1.0 || frame.size.height < 1.0) return NO;
    if (scale <= 0.0) scale = 1.0;

    _session = session;
    _pixelSize = CGSizeMake(floor(frame.size.width * scale), floor(frame.size.height * scale));
    _pixelBufferBytes = (uint32_t)(_pixelSize.width * _pixelSize.height * 4.0);
    if (_pixelBufferBytes == 0) return NO;

    _localPixels = calloc(1, _pixelBufferBytes);
    if (!_localPixels) return NO;

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    _localContext = CGBitmapContextCreate(_localPixels,
                                          (size_t)_pixelSize.width,
                                          (size_t)_pixelSize.height,
                                          8,
                                          (size_t)_pixelSize.width * 4,
                                          colorSpace,
                                          px_bitmap_info());
    CGColorSpaceRelease(colorSpace);
    if (!_localContext) return NO;

    CGFloat windowLevel = level;
    CGRect imageFrame = CGRectMake(0.0, 0.0, frame.size.width, frame.size.height);

    __block const char *failStage = "none";
    __block uint64_t window = 0;
    __block uint64_t imageView = 0;
    __block uint64_t pixelBuffer = 0;
    __block uint64_t context = 0;
    __block BOOL ok = NO;

    uint32_t previousSettle = r_settle_us(0);

    remote_call_with_session(session, ^{
        uint64_t windowClass = r_class("UIWindow");
        uint64_t windowAlloc = px_msg(windowClass, @"alloc", 0, 0, 0, 0);
        if (!r_is_objc_ptr(windowAlloc)) { failStage = "UIWindow alloc"; return; }

        // 没有 scene 的 UIWindow 在 iOS 13+ 不会进显示链，所以这里不退到
        // initWithFrame:，直接报错，免得「创建成功但看不见」。
        if (!r_is_objc_ptr(scene)) { failStage = "no windowScene"; return; }
        window = px_msg(windowAlloc, @"initWithWindowScene:", scene, 0, 0, 0);
        if (r_is_objc_ptr(window)) {
            r_msg2_main_raw(window, "setFrame:", &frame, sizeof(frame), NULL, 0, NULL, 0, NULL, 0);
        }
        if (!r_is_objc_ptr(window)) { failStage = "initWithWindowScene"; return; }

        r_msg2_main_raw(window, "setWindowLevel:", &windowLevel, sizeof(windowLevel),
                        NULL, 0, NULL, 0, NULL, 0);
        px_msg(window, @"setOpaque:", 0, 0, 0, 0);
        px_msg(window, @"setUserInteractionEnabled:", 0, 0, 0, 0);
        uint64_t clear = px_msg(r_class("UIColor"), @"clearColor", 0, 0, 0, 0);
        if (r_is_objc_ptr(clear)) px_msg(window, @"setBackgroundColor:", clear, 0, 0, 0);

        uint64_t imageAlloc = px_msg(r_class("UIImageView"), @"alloc", 0, 0, 0, 0);
        imageView = r_is_objc_ptr(imageAlloc)
            ? r_msg2_main_raw(imageAlloc, "initWithFrame:", &imageFrame, sizeof(imageFrame),
                              NULL, 0, NULL, 0, NULL, 0)
            : 0;
        if (!r_is_objc_ptr(imageView)) { failStage = "UIImageView init"; return; }

        px_msg(imageView, @"setUserInteractionEnabled:", 0, 0, 0, 0);
        px_msg(imageView, @"setContentMode:", 1, 0, 0, 0);   // scaleAspectFit
        if (r_is_objc_ptr(clear)) px_msg(imageView, @"setBackgroundColor:", clear, 0, 0, 0);
        px_msg(window, @"addSubview:", imageView, 0, 0, 0);
        // 顺序照抄仓库里能显示的那个悬浮窗：先加子视图，最后才取消隐藏
        px_msg(window, @"setHidden:", 0, 0, 0, 0);

        // 远程像素缓冲 + CGBitmapContext（数据直接指向它，之后 memcpy 即可）
        pixelBuffer = r_dlsym_call(R_TIMEOUT, "malloc", _pixelBufferBytes, 0, 0, 0, 0, 0, 0, 0);
        if (!r_is_objc_ptr(pixelBuffer)) { failStage = "malloc pixels"; return; }

        uint64_t colorSpaceRemote = r_dlsym_call(R_TIMEOUT, "CGColorSpaceCreateDeviceRGB", 0, 0, 0, 0, 0, 0, 0, 0);
        if (!r_is_objc_ptr(colorSpaceRemote)) { failStage = "CGColorSpace"; return; }

        context = r_dlsym_call(R_TIMEOUT, "CGBitmapContextCreate",
                               pixelBuffer,
                               (uint64_t)_pixelSize.width,
                               (uint64_t)_pixelSize.height,
                               8,
                               (uint64_t)_pixelSize.width * 4,
                               colorSpaceRemote,
                               (uint64_t)px_bitmap_info(),
                               0);
        if (!r_is_objc_ptr(context)) { failStage = "CGBitmapContextCreate"; return; }

        // 关联到 UIApplication，避免窗口被释放；三块视图必须用不同的 key，
        // 共用一个 key 会互相顶掉引用。
        uint64_t app = px_msg(r_class("UIApplication"), @"sharedApplication", 0, 0, 0, 0);
        _assocKey = px_sel([NSString stringWithFormat:@"cyanidePixelViewWindow%lu",
                            (unsigned long)(++gPxAssocSeed)]);
        if (r_is_objc_ptr(app) && _assocKey) {
            r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, _assocKey, window, 1, 0, 0, 0, 0);
        }

        ok = YES;
    });

    r_settle_us(previousSettle);
    if (!ok) cyanide_log(@"[PIXEL] setup failed at stage: %s", failStage);

    if (!ok) {
        cyanide_log(@"[PIXEL] setup failed %.0fx%.0f @%.1fx", frame.size.width, frame.size.height, scale);
        if (_localContext) { CGContextRelease(_localContext); _localContext = NULL; }
        if (_localPixels) { free(_localPixels); _localPixels = NULL; }
        return NO;
    }

    _window = window;
    _imageView = imageView;
    _pixelBuffer = pixelBuffer;
    _context = context;

    _imageClass = r_class("UIImage");
    _selAlloc = px_sel(@"alloc");
    _selInitWithCGImage = px_sel(@"initWithCGImage:");
    _selPerformOnMain = px_sel(@"performSelectorOnMainThread:withObject:waitUntilDone:");
    _selSetImage = px_sel(@"setImage:");
    _selRelease = px_sel(@"release");

    _ready = YES;
    cyanide_log(@"[PIXEL] ready win=0x%llx iv=0x%llx buf=0x%llx ctx=0x%llx %.0fx%.0f px",
                window, imageView, pixelBuffer, context, _pixelSize.width, _pixelSize.height);
    return YES;
}

- (uint64_t)window { return _window; }
- (uint64_t)imageView { return _imageView; }
- (BOOL)ready { return _ready; }
- (NSUInteger)lastCallCount { return _lastCallCount; }
- (double)lastUpdateMS { return _lastUpdateMS; }
- (CGSize)pixelSize { return _pixelSize; }

- (BOOL)blitImage:(UIImage *)image
{
    if (!image) return NO;
    return [self blitWithScale:1.0 draw:^(CGContextRef ctx, CGSize pointSize) {
        CGContextDrawImage(ctx, CGRectMake(0.0, 0.0, pointSize.width, pointSize.height), image.CGImage);
    }];
}

- (BOOL)blitWithScale:(CGFloat)scale draw:(void (^)(CGContextRef ctx, CGSize pointSize))draw
{
    if (!_ready || !_session || !draw) return NO;
    if (!r_is_objc_ptr(_pixelBuffer) || !r_is_objc_ptr(_context)) return NO;
    if (scale <= 0.0) scale = 1.0;

    NSTimeInterval begin = CACurrentMediaTime();

    CGContextClearRect(_localContext, CGRectMake(0.0, 0.0, _pixelSize.width, _pixelSize.height));
    CGContextSaveGState(_localContext);
    CGContextScaleCTM(_localContext, scale, scale);
    draw(_localContext, CGSizeMake(_pixelSize.width / scale, _pixelSize.height / scale));
    CGContextRestoreGState(_localContext);
    CGContextFlush(_localContext);

    RemoteCallSession *session = _session;
    uint64_t buffer = _pixelBuffer;
    uint64_t context = _context;
    uint64_t imageView = _imageView;
    uint64_t lastImage = _lastImage;
    const void *pixels = _localPixels;
    uint64_t bytes = (uint64_t)_pixelBufferBytes;
    uint64_t imageClass = _imageClass;
    uint64_t selAlloc = _selAlloc;
    uint64_t selInit = _selInitWithCGImage;
    uint64_t selPerform = _selPerformOnMain;
    uint64_t selSetImage = _selSetImage;
    uint64_t selRelease = _selRelease;

    __block NSUInteger calls = 0;
    __block uint64_t newImage = 0;
    __block BOOL ok = NO;

    remote_call_with_session(session, ^{
        if (!remote_write(buffer, pixels, bytes)) {
            cyanide_log(@"[PIXEL] remote_write failed (%llu bytes)", bytes);
            return;
        }

        uint64_t cgImage = r_dlsym_call(R_TIMEOUT, "CGBitmapContextCreateImage", context, 0, 0, 0, 0, 0, 0, 0);
        calls += 1;
        if (!r_is_objc_ptr(cgImage)) return;

        uint64_t allocated = r_msg(imageClass, selAlloc, 0, 0, 0, 0);
        calls += 1;
        if (!r_is_objc_ptr(allocated)) {
            r_dlsym_call(R_TIMEOUT, "CGImageRelease", cgImage, 0, 0, 0, 0, 0, 0, 0);
            return;
        }

        uint64_t uiImage = r_msg(allocated, selInit, cgImage, 0, 0, 0);
        calls += 1;
        if (!r_is_objc_ptr(uiImage)) {
            r_dlsym_call(R_TIMEOUT, "CGImageRelease", cgImage, 0, 0, 0, 0, 0, 0, 0);
            return;
        }

        // 一条消息把 setImage: 甩到 SpringBoard 主线程（waitUntilDone:YES）
        r_msg(imageView, selPerform, selSetImage, uiImage, 1, 0);
        calls += 1;

        r_msg(uiImage, selRelease, 0, 0, 0, 0);
        calls += 1;

        // 上一帧的 CGImage：视图已经换了新图，我们这份 +1 可以放了
        if (r_is_objc_ptr(lastImage)) {
            r_dlsym_call(R_TIMEOUT, "CGImageRelease", lastImage, 0, 0, 0, 0, 0, 0, 0);
            calls += 1;
        }

        newImage = cgImage;
        ok = YES;
    });

    if (ok && r_is_objc_ptr(newImage)) _lastImage = newImage;

    _lastCallCount = calls;
    _lastUpdateMS = (CACurrentMediaTime() - begin) * 1000.0;
    return ok;
}

- (void)detach
{
    RemoteCallSession *session = _session;
    uint64_t window = _window;
    uint64_t imageView = _imageView;
    uint64_t context = _context;
    uint64_t buffer = _pixelBuffer;
    uint64_t lastImage = _lastImage;
    uint64_t assocKey = _assocKey;

    if (session) {
        uint32_t previousSettle = r_settle_us(0);
        remote_call_with_session(session, ^{
            if (r_is_objc_ptr(imageView)) px_msg(imageView, @"setImage:", 0, 0, 0, 0);
            if (r_is_objc_ptr(window)) px_msg(window, @"setHidden:", 1, 0, 0, 0);
            if (r_is_objc_ptr(lastImage)) {
                r_dlsym_call(R_TIMEOUT, "CGImageRelease", lastImage, 0, 0, 0, 0, 0, 0, 0);
            }
            if (r_is_objc_ptr(context)) {
                r_dlsym_call(R_TIMEOUT, "CGContextRelease", context, 0, 0, 0, 0, 0, 0, 0);
            }
            if (r_is_objc_ptr(buffer)) {
                r_dlsym_call(R_TIMEOUT, "free", buffer, 0, 0, 0, 0, 0, 0, 0);
            }
            uint64_t app = px_msg(r_class("UIApplication"), @"sharedApplication", 0, 0, 0, 0);
            if (r_is_objc_ptr(app) && assocKey) {
                r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, assocKey, 0, 1, 0, 0, 0, 0);
            }
        });
        r_settle_us(previousSettle);
    }

    if (_localContext) { CGContextRelease(_localContext); _localContext = NULL; }
    if (_localPixels) { free(_localPixels); _localPixels = NULL; }

    _window = 0;
    _imageView = 0;
    _context = 0;
    _pixelBuffer = 0;
    _lastImage = 0;
    _ready = NO;
    _session = nil;
}

@end
