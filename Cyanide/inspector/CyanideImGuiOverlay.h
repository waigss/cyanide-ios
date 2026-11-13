//
//  CyanideImGuiOverlay.h
//  Cyanide
//
//  全局悬浮窗 = 全屏透明矢量画布 + ImGui 样子的小面板。
//
//      canvasWindow   level 1e6     全屏 · 透明 · 不吃触摸（点击穿透）
//        └─ CAShapeLayer            画线走这里：远程建 CGPath，渲染服务器合成
//      panelWindow    level 1e6+1   只有面板大小，上面叠隐形 UIKit 控件收输入
//      bubbleWindow   level 1e6+1   面板收起后留一颗圆钮
//
//  画线不再是「整屏截图推过去」：那是每帧 encode + 拷贝 + decode + 一次
//  NSInvocation（内部几十次远程调用），一帧几百毫秒。现在一帧只发
//  4 + 折线条数 次单条远程调用，几毫秒。
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

#pragma mark - 画布（屏幕坐标，原点左上）

// 一次替换画布上的所有折线。每个数组是一条折线，元素是 NSValue 包的 CGPoint。
- (void)setStrips:(NSArray<NSArray<NSValue *> *> *)strips;
- (void)drawPolyline:(NSArray<NSValue *> *)points;      // 追加一条
- (void)drawLineFrom:(CGPoint)from to:(CGPoint)to;      // 追加一条两点折线
- (void)drawCircleAt:(CGPoint)center radius:(CGFloat)radius segments:(NSUInteger)segments;
- (void)clearCanvas;

@property (nonatomic) BOOL demoEnabled;      // 旋转辐条演示（用来量帧率）
@property (nonatomic) BOOL gridEnabled;      // 静态网格层
@property (nonatomic) CGFloat lineWidth;     // 1..8
@property (nonatomic, strong) UIColor *strokeColor;

@end

NS_ASSUME_NONNULL_END
