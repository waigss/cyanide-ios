//
//  CyanideLog.m
//  Cyanide
//

#import "CyanideLog.h"

#import <stdio.h>

static NSMutableArray<NSString *> *gLines = nil;
static dispatch_queue_t gQueue = NULL;
static NSString *gFilePath = nil;
static NSDateFormatter *gFormatter = nil;

void cyanide_log_init(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gLines = [NSMutableArray array];
        gQueue = dispatch_queue_create("com.cyanide.log", DISPATCH_QUEUE_SERIAL);

        gFormatter = [[NSDateFormatter alloc] init];
        gFormatter.dateFormat = @"HH:mm:ss.SSS";

        NSString *documents =
            NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gFilePath = [documents stringByAppendingPathComponent:@"cyanide.log"];
    });
}

NSString *cyanide_log_file_path(void)
{
    cyanide_log_init();
    return gFilePath;
}

static void clog_append_to_file(NSString *line)
{
    if (gFilePath.length == 0) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:gFilePath]) {
        [fm createFileAtPath:gFilePath contents:nil attributes:nil];
    }

    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:gFilePath];
    if (!handle) return;

    NSData *data = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    @try {
        [handle seekToEndOfFile];
        [handle writeData:data];
    } @catch (__unused NSException *e) {
        // 磁盘满之类的异常不该把调用方拖死
    } @finally {
        [handle closeFile];
    }
}

void cyanide_log(NSString *format, ...)
{
    if (format.length == 0) return;

    cyanide_log_init();

    va_list args;
    va_start(args, format);
    NSString *body = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    if (body.length == 0) return;

    NSString *stamp = [gFormatter stringFromDate:[NSDate date]];
    NSString *line = [NSString stringWithFormat:@"%@ %@", stamp, body];

    printf("[CYANIDE] %s\n", line.UTF8String);

    dispatch_async(gQueue, ^{
        [gLines addObject:line];
        // 防止长时间运行吃内存：超过 4000 行丢掉最旧的 1000 行
        if (gLines.count > 4000) {
            [gLines removeObjectsInRange:NSMakeRange(0, 1000)];
        }
        clog_append_to_file(line);
    });
}

NSArray<NSString *> *cyanide_log_lines(void)
{
    cyanide_log_init();

    __block NSArray<NSString *> *snapshot = @[];
    dispatch_sync(gQueue, ^{
        snapshot = [gLines copy];
    });
    return snapshot;
}

void cyanide_log_clear(void)
{
    cyanide_log_init();
    dispatch_async(gQueue, ^{
        [gLines removeAllObjects];
    });
}
