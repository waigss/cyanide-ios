//
//  CyanideImGuiOverlay.h
//  Cyanide
//
//  全局悬浮窗：ImGui 风格界面 + 全屏透明画布。
//
//  结构（全部在 SpringBoard 进程里用远程调用搭出来）：
//
//      canvasWindow  level 1e6    全屏、透明、userInteractionEnabled=NO —— 点击穿透
//        └─ UIImageView            Cyanide 本地渲染好的整帧位图
//      panelWindow   level 1e6+1  只有面板大小，上面叠一组隐形 UIKit 控件收输入
//      bubbleWindow  level 1e6+1  面板收起后留一个圆形按钮
//
//  可见的像素全部来自本进程 CoreGraphics 渲染的 PNG：ImGui 的窗口/边框/
//  复选框/滑条都画在这张图里，远程进程只负责把图贴到窗口上。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface CyanideImGuiOverlay : NSObject

+ (instancetype)sharedOverlay;

@property (nonatomic, readonly, getter=isActive) BOOL active;
@property (nonatomic, readonly, getter=isStarting) BOOL starting;
@property (nonatomic, readonly) NSString *statusLine;

- (void)start;
- (void)stop;

#pragma mark - 全屏透明画布（线程安全，坐标是屏幕 point）

- (void)clearCanvas;
- (void)drawLineFrom:(CGPoint)from to:(CGPoint)to color:(UIColor *)color width:(CGFloat)width;
- (void)drawRect:(CGRect)rect color:(UIColor *)color width:(CGFloat)width;
- (void)drawCircleAt:(CGPoint)center radius:(CGFloat)radius color:(UIColor *)color width:(CGFloat)width;
- (void)drawText:(NSString *)text at:(CGPoint)point size:(CGFloat)size color:(UIColor *)color;

- (void)requestRedraw;

// 画布内容变了会自己重绘；这个开关控制的是演示动画（不用外部喂数据也能看到线）。
@property (nonatomic) BOOL demoEnabled;
@property (nonatomic) BOOL gridEnabled;

@end

NS_ASSUME_NONNULL_END
