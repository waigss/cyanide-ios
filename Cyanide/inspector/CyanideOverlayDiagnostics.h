//
//  CyanideOverlayDiagnostics.h
//  Cyanide
//
//  全局悬浮窗自检：把 SpringBoard 里的真实状态读回到 App 自己的界面上。
//
//  为什么要这个：远程建的窗口在 SpringBoard 里，用户看不到任何日志；而
//  「日志全对、屏幕全空」已经出现过多次。这个页面把窗口句柄、hidden、
//  isKeyWindow、是否进了 UIApplication.windows、label 的 superview 等
//  全部读回来显示，一次就能定位问题在哪一层。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface CyanideOverlayDiagnostics : NSObject

// 阻塞式采集（内部会建 SpringBoard 会话）。请在后台队列调用。
+ (NSString *)collectReport;

// 采集并显示在一个可滚动的页面里。
+ (void)presentFrom:(UIViewController *)presenter;

@end

NS_ASSUME_NONNULL_END
