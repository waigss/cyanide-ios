//
//  ProcessDetailViewController.h
//  Cyanide
//
//  某个进程的库列表：主程序 / 第三方库 / 系统库，每项带 ASLR 后的加载基址。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ProcessDetailViewController : UITableViewController

// procAddr 是内核里 struct proc 的地址（来自 proc_list_all）。传 0 时退回按名字查找。
- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr;

@end

NS_ASSUME_NONNULL_END
