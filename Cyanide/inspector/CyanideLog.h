//
//  CyanideLog.h
//  Cyanide
//
//  极简中文诊断日志：内存环形缓冲 + 同步写一份到 Documents/cyanide.log，
//  方便在设备上直接看，也方便把文件导出来分析。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// 初始化（首次调用 clog 时会自动调用，可重复调用）。
void clog_init(void);

// 记录一行。自带时间戳；同时 printf 到系统日志、追加到文件。
void clog(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);

// 当前缓冲区里的所有行（拷贝）。
NSArray<NSString *> *clog_lines(void);

// 清空内存缓冲（文件保留）。
void clog_clear(void);

// 日志文件路径。
NSString *clog_file_path(void);

NS_ASSUME_NONNULL_END
