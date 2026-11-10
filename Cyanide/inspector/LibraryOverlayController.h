//
//  LibraryOverlayController.h
//  Cyanide
//
//  在 SpringBoard 里挂一个悬浮窗：显示指定进程（默认 smoba）加载的库与基址。
//
//  窗口里带一个「执行」开关：按下时本进程会先确保内核读写就绪，再重新查找目标
//  进程并读取它的库列表。窗口每 3 秒自动刷新一次。
//
//  为什么要放在 SpringBoard：普通 App 无法覆盖别的 App，只有 SpringBoard 的窗口
//  能浮在任意前台 App 之上（项目已有同类实现：tweaks/statbar.m、tweaks/notepad_tweak.m）。
//
//  为什么要保活：读库要在本进程里附着目标进程，而目标只有在前台时才有可劫持线程；
//  本 App 切后台后靠静音音频保活，才能在你打开目标 App 时继续刷新悬浮窗。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LibraryOverlayController : NSObject

+ (instancetype)sharedOverlay;

// 悬浮窗是否在工作。
@property (nonatomic, readonly, getter=isActive) BOOL active;

// 用户是否主动关掉过（SceneDelegate 用它决定下次进前台要不要自动挂出来）。
@property (nonatomic, readonly) BOOL dismissed;

// 悬浮窗当前绑定的进程名。
@property (nonatomic, copy, readonly, nullable) NSString *activeProcessName;

// 为指定进程悬浮显示库列表。procAddr 传 0 时每轮按名字重新查找。
- (void)startForProcessName:(NSString *)processName
                        pid:(int)pid
                   procAddr:(uint64_t)procAddr;

// 启动时自动接管：绑定进程名、自动初始化内核、出窗后每 3 秒刷新。
- (void)autoStartForProcessName:(NSString *)processName;

// 关掉悬浮窗并清理远程对象。
- (void)stop;

// 用户主动关闭（区别于内部重启），会记住 dismissed 状态。
- (void)stopByUser;

@end

NS_ASSUME_NONNULL_END
