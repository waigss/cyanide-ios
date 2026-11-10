//
//  ProcessDetailViewController.h
//  Cyanide
//
//  某个进程的模块（已加载 image）列表：名称 + ASLR 后的加载基址 + 路径。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ProcessDetailViewController : UITableViewController

- (instancetype)initWithProcessName:(NSString *)processName pid:(int)pid;

@end

NS_ASSUME_NONNULL_END
