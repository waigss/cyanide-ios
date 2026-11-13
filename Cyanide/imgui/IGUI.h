//
//  IGUI.h
//  Cyanide
//
//  极简 immediate-mode UI，接口形状照 Dear ImGui 来（Begin/End + 逐行控件），
//  输出 IGdrawList 图元。它画在 Cyanide 进程里，结果作为一张透明位图推到
//  SpringBoard 的悬浮窗上，所以同一份界面代码既能截图调试，也能全局显示。
//
//  交互不走这里的命中测试：远程进程里没法跑我们的代码，输入由
//  CyanideImGuiOverlay 用一组隐形的 UIKit 控件（UISwitch/UISlider/
//  UISegmentedControl）叠在对应位置轮询 state 完成。lastItemRect 就是给那层
//  控件对位置用的。
//

#import <UIKit/UIKit.h>
#import "IGDrawList.h"

NS_ASSUME_NONNULL_BEGIN

typedef struct IGStyle {
    CGFloat windowPaddingX;
    CGFloat windowPaddingY;
    CGFloat itemSpacingY;
    CGFloat fontSize;
    CGFloat titleHeight;
    CGFloat windowRounding;
    CGFloat frameRounding;
    CGFloat borderSize;
    CGFloat sliderHeight;
    CGFloat grabWidth;
    CGFloat checkboxSize;
    CGFloat buttonHeight;
    CGFloat tabHeight;

    uint32_t colWindowBg;
    uint32_t colTitleBg;
    uint32_t colTitleBgActive;
    uint32_t colBorder;
    uint32_t colFrameBg;
    uint32_t colFrameBgHovered;
    uint32_t colCheckMark;
    uint32_t colText;
    uint32_t colTextDisabled;
    uint32_t colSeparator;
    uint32_t colSliderGrab;
    uint32_t colSliderGrabActive;
    uint32_t colButton;
    uint32_t colButtonHovered;
    uint32_t colTab;
    uint32_t colTabActive;
} IGStyle;

IGStyle IGStyleDefault(void);

@interface IGUI : NSObject

@property (nonatomic, strong, readonly) IGDrawList *drawList;
@property (nonatomic) IGStyle style;

// 最近一次控件占用的屏幕矩形（input 层用它摆隐形控件）。
@property (nonatomic, readonly) CGRect lastItemRect;

- (void)beginFrameWithDisplaySize:(CGSize)size;
- (void)endFrame;

// 先量后画：measure 只跑布局不产生图元，返回内容高度（不含标题栏和内边距）。
- (CGFloat)measureWithWidth:(CGFloat)width build:(void (^)(void))build;

- (void)beginWindow:(NSString *)title frame:(CGRect)frame;
- (void)endWindow;

- (void)text:(NSString *)text;
- (void)textDisabled:(NSString *)text;
- (void)textColored:(uint32_t)color text:(NSString *)text;
- (void)separator;
- (void)checkbox:(NSString *)label value:(BOOL)value;
- (void)sliderFloat:(NSString *)label
              value:(CGFloat)value
                min:(CGFloat)min
                max:(CGFloat)max
          valueText:(NSString *)valueText;

// 离散档位滑条（ImGui SliderInt 的观感）。远程侧对应 UISegmentedControl，
// 因为 float 返回值不在 x0 里，读不回来；NSInteger 可以。
- (void)sliderIntTicks:(NSString *)label
                 value:(NSInteger)value
                   min:(NSInteger)min
                   max:(NSInteger)max
             valueText:(NSString *)valueText;
- (void)button:(NSString *)label;
- (void)tabBar:(NSArray<NSString *> *)labels active:(NSInteger)active;

@end

NS_ASSUME_NONNULL_END
