//
//  ProbeListViewController.h
//  Cyanide
//
//  探针表：以主程序模块基址为基准，按「文件名 / 偏移 / 字节数」批量读取并落盘。
//  表内容来自 Documents/dumps/probes.txt，可随时编辑，不用重新编译。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ProbeListViewController : UITableViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr;

@end

NS_ASSUME_NONNULL_END
