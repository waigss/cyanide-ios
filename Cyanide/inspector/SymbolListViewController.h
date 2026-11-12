//
//  SymbolListViewController.h
//  Cyanide
//
//  符号页：解析目标模块 Mach-O 的 LC_SYMTAB，列出函数/符号名与运行时地址。
//  数据来源是内核页表直读（不附加），所以目标挂起也能用。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface SymbolListViewController : UITableViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr
                         moduleBase:(uint64_t)moduleBase
                         moduleName:(NSString *)moduleName;

@end

NS_ASSUME_NONNULL_END
