//
//  LibraryOverlayController.h
//  Cyanide
//
//  在 SpringBoard 里开一个悬浮窗，显示某个进程当前加载的库与基址。
//
//  为什么要在 SpringBoard 里开窗：普通 App 无法覆盖别的 App，只有 SpringBoard
//  的窗口能在任意前台 App 之上显示；本 App 已经在走这条路径（见 tweaks/statbar.m
//  与 notepad_tweak.m）。
//
//  为什么要保活：读库需要在本进程里发起 RemoteCall 附着到目标进程，而目标 App
//  只有在前台时才有可劫持的线程。本 App 切到后台后靠静音音频保活，才能在你打开
//  目标 App 时继续探测并更新悬浮窗。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LibraryOverlayController : NSObject

+ (instancetype)sharedOverlay;

// 当前是否有悬浮窗在工作。
- (BOOL)isActive;

// 悬浮窗当前绑定的进程名（没有则为 nil）。
- (nullable NSString *)activeProcessName;

// 开始为某个进程悬浮显示库列表。procAddr 传 0 时退回按名字查找。
- (void)startForProcessName:(NSString *)processName
                        pid:(int)pid
                   procAddr:(uint64_t)procAddr;

// 关掉悬浮窗并清理远程对象。
- (void)stop;

@end

NS_ASSUME_NONNULL_END
