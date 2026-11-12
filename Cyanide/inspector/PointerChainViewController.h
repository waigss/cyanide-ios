//
//  PointerChainViewController.h
//  Cyanide
//
//  指针链读取页：按「基址 + 偏移 → 解引用 → +偏移 → … → 读值」逐级解析并显示每一级。
//  链内容是一段可编辑脚本（默认保存在 Documents/dumps/chain.txt），换偏移不用重新编译。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface PointerChainViewController : UIViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr;

@end

NS_ASSUME_NONNULL_END
