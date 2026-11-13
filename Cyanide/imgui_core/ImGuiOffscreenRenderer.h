//
//  ImGuiOffscreenRenderer.h
//  Cyanide
//
//  把 ImGui 渲染到一张离屏 MTLTexture，再读回 CPU 像素（BGRA，alpha 预乘）。
//  产物直接交给 CyanidePixelView 推到 SpringBoard 的全局窗口。
//
//  和 ImGuiViewController 的区别：那个用 CAMetalLayer 直接显示在 App 窗口里，
//  这个不碰屏幕，只出像素。
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

@interface ImGuiOffscreenRenderer : NSObject

// pixelWidth/pixelHeight 是像素尺寸，scale 是 point → 像素的倍率。
- (nullable instancetype)initWithPixelWidth:(NSUInteger)pixelWidth
                                pixelHeight:(NSUInteger)pixelHeight
                                      scale:(CGFloat)scale;

@property (nonatomic, readonly) BOOL ready;
@property (nonatomic, readonly) NSUInteger pixelWidth;
@property (nonatomic, readonly) NSUInteger pixelHeight;
@property (nonatomic, readonly) NSUInteger byteLength;

// 渲染一帧：block 里正常调用 ImGui::Begin/End 等。
// 返回 YES 后 pixels 指向这一帧的 BGRA 数据（生命周期到下一次 renderFrame）。
- (BOOL)renderFrame:(void (^)(void))buildBlock;

@property (nonatomic, readonly) const void *pixels;

// 直接画「全局覆盖」那一套 UI（统计窗口 + 可选 ImGui demo 窗口）。
// 把 ImGui 的 C++ 调用关在这个 .mm 里，调用方保持纯 ObjC。
- (BOOL)renderOverlayFrameWithFPS:(double)fps
                          frameMS:(double)frameMS
                        callCount:(NSUInteger)callCount
                         showDemo:(BOOL)showDemo;

- (void)shutdown;

@end

NS_ASSUME_NONNULL_END
