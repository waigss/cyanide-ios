//
//  CyanidePixelView.h
//  Cyanide
//
//  一块「远程位图视图」：自己在 SpringBoard 里建窗口 + UIImageView，并把本进程渲染
//  好的像素整帧推过去。
//
//  为什么是位图而不是 CGPath/CAShapeLayer：
//    ImGui 这类立即模式 UI 的产物就是一张位图，描边路径只能表达线，没法表达文字、
//    圆角、混合。位图这条路每帧的远程调用是常数（6 次单条调用），瓶颈变成一次
//    memcpy —— 而 memcpy 是本进程内的内存带宽，不是 mach IPC。
//
//  每帧：
//    remote_write(像素)                      0 次远程调用（共享页 memcpy）
//    CGBitmapContextCreateImage(context)     1
//    +[UIImage alloc]                        1
//    -[UIImage initWithCGImage:]             1
//    performSelectorOnMainThread:setImage:   1   ← 一条消息把调用甩到主线程
//    -[UIImage release]                      1
//    CGImageRelease(上一帧的 CGImage)         1
//                                           ─
//                                           6
//
//  远程的 CGBitmapContext 只建一次：它直接写在我们 malloc 出来的那块远程内存上，
//  于是「推帧」等于往那块内存 memcpy，CGImage 只是给它套一层快照。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@class RemoteCallSession;

NS_ASSUME_NONNULL_BEGIN

@interface CyanidePixelView : NSObject

// frame 是逻辑尺寸（point），scale 是像素倍率。窗口层级 level 越大越靠上。
+ (nullable instancetype)viewWithSession:(RemoteCallSession *)session
                                   scene:(uint64_t)scene
                                   frame:(CGRect)frame
                                   level:(CGFloat)level
                                   scale:(CGFloat)scale;

@property (nonatomic, readonly) uint64_t window;
@property (nonatomic, readonly) uint64_t imageView;
@property (nonatomic, readonly) BOOL ready;

@property (nonatomic, readonly) NSUInteger lastCallCount;
@property (nonatomic, readonly) double lastUpdateMS;
@property (nonatomic, readonly) CGSize pixelSize;

// 直接把一帧画进本地位图并推过去。block 里的 ctx 已经按 point 坐标缩放过，
// 所以 IGDrawList 的 drawIntoContext: 可以直接用。
- (BOOL)blitWithScale:(CGFloat)scale draw:(void (^)(CGContextRef ctx, CGSize pointSize))draw;

// 方便的一次性接口（内部包一层 blitWithScale:）。
- (BOOL)blitImage:(nullable UIImage *)image;

// 真正把窗口挂上显示的一步：setHidden:0 + makeKeyAndVisible。
// 只在需要接收/显示的窗口上调（画布、面板），隐藏的小圆钮不要调。
- (void)makeKeyAndVisible;

// 直接把一整帧 BGRA（alpha 预乘）推过去，跳过 CoreGraphics 绘制。
// 用于 ImGui 离屏渲染出来的像素。
- (BOOL)blitPixels:(const void *)pixels byteLength:(NSUInteger)byteLength;
- (void)detach;

@end

NS_ASSUME_NONNULL_END
