//
//  IGDrawList.h
//  Cyanide
//
//  ImGui 风格图元列表 + CoreGraphics 光栅化。
//
//  设计要点（和 Dear ImGui 的 ImDrawList 对齐）：
//    * 只存「图元」，不持有任何 UIView，绘制链完全在 Cyanide 进程里跑；
//    * 坐标是屏幕 point，原点左上、y 向下（UIKit 坐标系），
//      这样同一份图元既能画在本地 UIImage，也能直接对回屏幕坐标；
//    * 渲染走 UIGraphicsImageRenderer + CoreText，不依赖主线程，可后台队列调用。
//
//  颜色统一用 0xAARRGGBB。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef struct IGVec2 {
    CGFloat x;
    CGFloat y;
} IGVec2;

static inline IGVec2 IGVec2Make(CGFloat x, CGFloat y)
{
    IGVec2 v;
    v.x = x;
    v.y = y;
    return v;
}

static inline CGFloat IGClamp01(CGFloat v)
{
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}

// 0xAARRGGBB
static inline uint32_t IGColorMake(CGFloat r, CGFloat g, CGFloat b, CGFloat a)
{
    uint32_t ri = (uint32_t)(IGClamp01(r) * 255.0 + 0.5);
    uint32_t gi = (uint32_t)(IGClamp01(g) * 255.0 + 0.5);
    uint32_t bi = (uint32_t)(IGClamp01(b) * 255.0 + 0.5);
    uint32_t ai = (uint32_t)(IGClamp01(a) * 255.0 + 0.5);
    return (ai << 24) | (ri << 16) | (gi << 8) | bi;
}

static inline uint32_t IGColorAlpha(uint32_t color, CGFloat a)
{
    uint32_t ai = (uint32_t)(IGClamp01(a) * 255.0 + 0.5);
    return (color & 0x00FFFFFFu) | (ai << 24);
}

static inline uint32_t IGColorBlend(uint32_t from, uint32_t to, CGFloat t)
{
    CGFloat k = IGClamp01(t);
    uint32_t fa = (from >> 24) & 0xFF, fr = (from >> 16) & 0xFF, fg = (from >> 8) & 0xFF, fb = from & 0xFF;
    uint32_t ta = (to >> 24) & 0xFF,   tr = (to >> 16) & 0xFF,   tg = (to >> 8) & 0xFF,   tb = to & 0xFF;
    uint32_t a = (uint32_t)((CGFloat)fa + ((CGFloat)ta - (CGFloat)fa) * k);
    uint32_t r = (uint32_t)((CGFloat)fr + ((CGFloat)tr - (CGFloat)fr) * k);
    uint32_t g = (uint32_t)((CGFloat)fg + ((CGFloat)tg - (CGFloat)fg) * k);
    uint32_t b = (uint32_t)((CGFloat)fb + ((CGFloat)tb - (CGFloat)fb) * k);
    return (a << 24) | (r << 16) | (g << 8) | b;
}

typedef NS_ENUM(NSInteger, IGDrawCmdType) {
    IGDrawCmdTypeLine = 0,
    IGDrawCmdTypeRect,
    IGDrawCmdTypeRectFilled,
    IGDrawCmdTypeCircle,
    IGDrawCmdTypeCircleFilled,
    IGDrawCmdTypeTriangleFilled,
    IGDrawCmdTypeText,
};

typedef struct IGDrawCmd {
    IGDrawCmdType type;
    IGVec2 a;
    IGVec2 b;
    IGVec2 c;
    uint32_t color;
    CGFloat thickness;
    CGFloat radius;
    CGFloat fontSize;
    char text[96];
} IGDrawCmd;

// 用 CoreText 量一段单行文本的宽度（point）。线程安全。
CGFloat IGTextWidth(NSString *text, CGFloat fontSize);

@interface IGDrawList : NSObject

@property (nonatomic, readonly) NSUInteger count;

- (void)reset;

- (void)addLineFrom:(IGVec2)from to:(IGVec2)to color:(uint32_t)color thickness:(CGFloat)thickness;
- (void)addRect:(CGRect)rect color:(uint32_t)color thickness:(CGFloat)thickness radius:(CGFloat)radius;
- (void)addRectFilled:(CGRect)rect color:(uint32_t)color radius:(CGFloat)radius;
- (void)addCircleAt:(IGVec2)center radius:(CGFloat)radius color:(uint32_t)color thickness:(CGFloat)thickness;
- (void)addCircleFilledAt:(IGVec2)center radius:(CGFloat)radius color:(uint32_t)color;
- (void)addTriangleFilled:(IGVec2)p0 :(IGVec2)p1 :(IGVec2)p2 color:(uint32_t)color;
- (void)addText:(NSString *)text at:(IGVec2)origin fontSize:(CGFloat)fontSize color:(uint32_t)color;

// 渲染成透明底 UIImage。scale 为像素倍率（2.0 = 2 倍图）。
- (nullable UIImage *)renderWithSize:(CGSize)size scale:(CGFloat)scale;

@end

NS_ASSUME_NONNULL_END
