//
//  MemoryReaderViewController.h
//  Cyanide
//
//  内存读取页：输入地址、选择数据类型读取值，并支持「跟随指针」逐级跳转。
//  底层走 KernelUserMemory 的内核页表直读，不附加目标进程。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface MemoryReaderViewController : UIViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr;

@end

NS_ASSUME_NONNULL_END
