//
//  ImGuiViewController.h
//  Cyanide
//
//  App 内的 ImGui 本地演示：Metal 后端 + 触摸输入。
//
//  这一份的目的不是最终形态，而是把「ImGui 能在这台设备上跑起来」这件事先确认掉：
//  它不碰内核、不碰 SpringBoard、不碰远程调用，纯粹是 App 自己的一个 ViewController。
//  跑通之后，同一份 ImDrawData 的像素就能交给 CyanidePixelView 推到全局窗口。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ImGuiViewController : UIViewController

// 从任意控制器 present 出来（全屏）。
+ (void)presentFrom:(UIViewController *)presenter;

@end

NS_ASSUME_NONNULL_END
