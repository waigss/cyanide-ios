//
//  CyanideScreenCanvas.h
//  Cyanide
//
//  全屏透明画布：在 SpringBoard 里挂一个不吃触摸的窗口，里面是 CAShapeLayer。
//  画线 = 把点数组写进共享页 + 让远程进程的 CoreGraphics 建一条 CGPath 设给图层，
//  由渲染服务器合成，不需要传位图。
//
//  一帧的远程调用次数（与点数量无关）：
//      CGPathCreateMutable              1
//      CGPathAddLines × 折线条数         N
//      -[CAShapeLayer setPath:]         1
//      CGPathRelease(上一帧的 path)      1
//      CATransactionCommit              1
//                                   ─────
//                                   4 + N
//
//  对比「整屏 PNG 推图」：那条路每帧要 encode + 几 MB 拷贝 + decode + NSInvocation
//  （一次 NSInvocation 内部就是几十次远程调用），一帧几百毫秒。这条路一帧几毫秒。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@class RemoteCallSession;

NS_ASSUME_NONNULL_BEGIN

@interface CyanideScreenCanvas : NSObject

+ (instancetype)sharedCanvas;

@property (nonatomic, readonly) BOOL attached;

// 上一帧的远程调用次数与耗时（毫秒），给面板显示用。
@property (nonatomic, readonly) NSUInteger lastCallCount;
@property (nonatomic, readonly) double lastUpdateMS;

// 把画布挂到指定 scene 上。scene 传 0 时退化成 initWithFrame。
- (BOOL)attachWithSession:(RemoteCallSession *)session
                    scene:(uint64_t)scene
               screenSize:(CGSize)screenSize;

- (void)detach;

// 每帧调用：strips 里每个数组是一条折线，元素是 NSValue 包的 CGPoint（屏幕坐标）。
// color / width 只在变化时才会走远程设置，重复传相同值不额外花钱。
- (void)setStrips:(NSArray<NSArray<NSValue *> *> *)strips
            color:(UIColor *)color
            width:(CGFloat)width;

// 清空动态图层（把 path 设成空）。
- (void)clear;

// 静态网格层：只在第一次打开时构建，之后开关就是一条 setHidden:。
- (void)setGridVisible:(BOOL)visible;

@end

NS_ASSUME_NONNULL_END
