//
//  ProcessListViewController.h
//  Cyanide
//
//  「进程」页：从内核 proc 链表实时读取当前所有进程的名称 / PID / UID。
//  只读展示，不做任何写操作。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ProcessListViewController : UITableViewController
@end

NS_ASSUME_NONNULL_END
