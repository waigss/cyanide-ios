//
//  ProcessDetailViewController.m
//  Cyanide
//
//  读取目标进程已加载的 image，并按「主程序 / 第三方库 / 系统库」分三组列出，
//  每项带 ASLR 后的加载基址。
//
//  实现：借 RemoteCallSession 在目标进程里执行 dyld 的公开 C 接口
//
//      _dyld_image_count()                  -> 模块数量
//      _dyld_get_image_header(i)            -> 第 i 个模块的加载基址（mach_header *）
//      _dyld_get_image_name(i)              -> 第 i 个模块的路径（目标进程内的 const char *）
//
//  分组规则：
//      index 0                -> 主程序（dyld 保证第 0 个 image 是可执行文件本身）
//      /var/ /private/var/ /Library/  -> 第三方库（App 自带库、TrollStore、越狱注入库都在这些前缀下）
//      其余（/usr/lib、/System/...）   -> 系统库
//
//  session 的建立/查询全在后台队列做，完成后再回主线程刷新。
//  整表可能几十到几百条，每条 1~2 次远程调用，所以加了总时长上限，
//  超时就返回已经拿到的部分并标注「结果不完整」。
//

#import "ProcessDetailViewController.h"

#import "../TaskRop/RemoteCall.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/kutils.h"
#import "../tweaks/remote_objc.h"
#import "../utils/sandbox.h"
#import "CyanideLog.h"
#import "../DSKeepAlive.h"

// 定义在 ViewController.m：借 SpringBoard 签发 "/" 的 read-write 扩展再本地 consume，
// 从而读得到别的 App 容器里的文件。
extern int escape_sbx_demo2(void);

// 拿到「能读 /private/var」的文件访问能力。已具备时直接返回，避免重复逃逸。
static BOOL cyanide_ensure_file_access(void)
{
    if (check_sandbox_var_rw() == 0) {
        cyanide_log(@"[文件访问] 已具备 /private/var 读写，跳过逃逸");
        return YES;
    }

    cyanide_log(@"[文件访问] 当前无 /private/var 读写，开始逃逸");

    int r1 = escape_sbx_demo2();
    int c1 = check_sandbox_var_rw();
    cyanide_log(@"[文件访问] escape_sbx_demo2()=%d 校验=%d", r1, c1);
    if (r1 == 0 && c1 == 0) return YES;

    int r2 = patch_sandbox_ext();
    int c2 = check_sandbox_var_rw();
    cyanide_log(@"[文件访问] patch_sandbox_ext()=%d 校验=%d", r2, c2);
    if (r2 == 0 && c2 == 0) return YES;

    int r3 = borrow_sandbox_ext("SpringBoard");
    int c3 = check_sandbox_var_rw();
    cyanide_log(@"[文件访问] borrow_sandbox_ext(SpringBoard)=%d 校验=%d", r3, c3);
    if (r3 == 0 && c3 == 0) return YES;

    cyanide_log(@"[文件访问] 三种方式全部失败");
    return NO;
}

static NSString * const kModuleCellIdentifier = @"CyanideModuleCell";
static const NSTimeInterval kModuleLoadDeadline = 30.0;
static const uint64_t kModuleCountLimit = 4096;

static NSString * const kGroupKindMain   = @"main";
static NSString * const kGroupKindThird  = @"third";
static NSString * const kGroupKindSystem = @"system";

typedef NS_ENUM(NSInteger, ModuleListState) {
    ModuleListStateIdle = 0,
    ModuleListStateLoading,
    ModuleListStateLoaded,
    ModuleListStateFailed,
};

@interface ProcessDetailViewController ()

@property (nonatomic, copy) NSString *processName;
@property (nonatomic, assign) int pid;
@property (nonatomic, assign) uint64_t procAddr;
@property (nonatomic, copy) NSString *loadingHintText;

// 每个元素：@{@"kind": 分组标识, @"title": 分组标题, @"items": @[ @{name,path,base} ]}
@property (nonatomic, copy) NSArray<NSDictionary<NSString *, id> *> *sections;
@property (nonatomic, assign) ModuleListState state;
@property (nonatomic, copy) NSString *failureReason;
@property (nonatomic, assign) BOOL truncated;

// 后台监听：目标被挂起时附加必然超时，所以等它真在跑的时候再读。
@property (nonatomic, assign) BOOL watching;
@property (nonatomic, strong) dispatch_source_t watchTimer;
@property (nonatomic, strong) dispatch_queue_t watchQueue;
@property (nonatomic, assign) NSUInteger watchAttempt;

@property (nonatomic, strong) UIView *placeholderView;
@property (nonatomic, strong) UILabel *placeholderLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;

@end

@implementation ProcessDetailViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _processName = [processName copy];
        _pid = pid;
        _procAddr = procAddr;
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = self.processName.length > 0 ? self.processName : @"库";
    self.tableView.rowHeight = 62.0;

    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"后台监听"
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(toggleBackgroundWatch)];

    [self buildPlaceholderView];
    [self loadModules];
}

- (void)presentAlertWithTitle:(NSString *)title message:(NSString *)message
{
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:title
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - 分组规则

static BOOL module_path_is_third_party(NSString *path)
{
    if (path.length == 0) return NO;
    if ([path hasPrefix:@"/var/"]) return YES;
    if ([path hasPrefix:@"/private/var/"]) return YES;
    if ([path hasPrefix:@"/Library/"]) return YES;
    return NO;
}

#pragma mark - 附加

// 依次尝试三种附加策略：
//   1. 普通 init_remote_call
//   2. MIG filter bypass（目标对 mach 消息有 filter 时用）
//   3. MIG filter bypass + original-thread-only（目标已有异常端口时用）
// procAddr 非 0 时直接把 g_RC_targetProcOverride 设成枚举到的 struct proc 地址，
// 这样不会被 proc_find_by_name 找到同名的另一个进程。
// 失败原因留在 remote_call_last_init_failure() 里，由调用方读取。
static RemoteCallSession *cyanide_attach_to_process(NSString *name,
                                                    uint64_t procAddr,
                                                    int timeoutMS,
                                                    void (^hint)(NSString *text))
{
    for (int attempt = 0; attempt < 3; attempt++) {
        NSString *strategy = attempt == 0 ? @"普通"
                            : (attempt == 1 ? @"MIG-filter-bypass" : @"original-thread-only");

        if (hint) {
            NSString *text = nil;
            if (attempt == 0) {
                text = @"正在附加到目标进程…";
            } else if (attempt == 1) {
                text = @"第一次附加没有成功，改用 MIG filter bypass 重试…";
            } else {
                text = @"还在失败，最后改用 original-thread-only 重试…";
            }
            hint(text);
        }

        cyanide_log(@"[附加] 目标=%@ proc=0x%llx 策略=%@ 超时=%dms", name, procAddr, strategy, timeoutMS);

        if (procAddr != 0) {
            g_RC_targetProcOverride = procAddr;
        }

        CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
        RemoteCallSession *session = nil;
        if (attempt == 0) {
            session = [[RemoteCallSession alloc] initWithProcess:name
                                             useMigFilterBypass:NO
                                        firstExceptionTimeoutMS:timeoutMS];
        } else if (attempt == 1) {
            session = [[RemoteCallSession alloc] initWithProcess:name
                                             useMigFilterBypass:YES
                                        firstExceptionTimeoutMS:timeoutMS];
        } else {
            session = [[RemoteCallSession alloc] initWithProcess:name
                                             useMigFilterBypass:YES
                                        firstExceptionTimeoutMS:timeoutMS
                                             originalThreadOnly:YES];
        }
        double elapsedMS = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0;

        if (session) {
            cyanide_log(@"[附加] 成功 策略=%@ 耗时=%.0fms 目标pid=%u",
                 strategy, elapsedMS, session.pid);
            return session;
        }

        g_RC_targetProcOverride = 0;

        RemoteCallInitFailure lastFailure = remote_call_last_init_failure();
        const char *desc = (lastFailure != RemoteCallInitFailureNone)
            ? remote_call_init_failure_description(lastFailure) : NULL;
        cyanide_log(@"[附加] 失败 策略=%@ 耗时=%.0fms 原因=%s(%d) 失败pid=%u krw_ready=%d self_proc=0x%llx",
             strategy, elapsedMS, desc ? desc : "未知", (int)lastFailure,
             remote_call_last_init_failure_pid(),
             kexploit_krw_ready() ? 1 : 0, proc_self());

        if (lastFailure == RemoteCallInitFailureKRWUnavailable ||
            lastFailure == RemoteCallInitFailureProcessMissing) {
            cyanide_log(@"[附加] 该原因重试无意义，停止");
            break;
        }
    }

    cyanide_log(@"[附加] 三种策略全部失败：目标=%@ proc=0x%llx", name, procAddr);
    return nil;
}

#pragma mark - 空状态

- (void)buildPlaceholderView
{
    UIView *container = [[UIView alloc] initWithFrame:CGRectZero];

    self.spinner = [[UIActivityIndicatorView alloc]
        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.hidesWhenStopped = YES;

    self.placeholderLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.placeholderLabel.numberOfLines = 0;
    self.placeholderLabel.textAlignment = NSTextAlignmentCenter;
    self.placeholderLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    self.placeholderLabel.textColor = [UIColor secondaryLabelColor];

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.spinner, self.placeholderLabel
    ]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentFill;
    stack.spacing = 16.0;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [container addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:container.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:container.centerYAnchor],
        [stack.widthAnchor   constraintLessThanOrEqualToConstant:320.0],
        [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:container.leadingAnchor constant:16.0],
    ]];

    self.placeholderView = container;
}

- (void)refreshPlaceholderState
{
    if (self.sections.count > 0) {
        self.tableView.backgroundView = nil;
        [self.spinner stopAnimating];
        return;
    }

    self.tableView.backgroundView = self.placeholderView;

    switch (self.state) {
        case ModuleListStateLoading:
            if (self.loadingHintText.length > 0) {
                self.placeholderLabel.text = self.loadingHintText;
            } else {
                self.placeholderLabel.text = [NSString stringWithFormat:
                    @"正在附加到 %@ (PID %d) 并读取库列表…\n首次附加可能要几秒。",
                    self.processName, self.pid];
            }
            [self.spinner startAnimating];
            break;
        case ModuleListStateFailed:
            self.placeholderLabel.text = self.failureReason ?: @"读取失败。";
            [self.spinner stopAnimating];
            break;
        case ModuleListStateLoaded:
            self.placeholderLabel.text = @"该进程没有加载任何库。";
            [self.spinner stopAnimating];
            break;
        case ModuleListStateIdle:
        default:
            self.placeholderLabel.text = @"";
            [self.spinner stopAnimating];
            break;
    }
}

#pragma mark - 读取

- (void)loadModules
{
    if (self.state == ModuleListStateLoading) return;

    self.state = ModuleListStateLoading;
    self.loadingHintText = nil;
    [self refreshPlaceholderState];

    NSString *name = [self.processName copy];
    uint64_t procAddr = self.procAddr;
    __weak typeof(self) weakSelf = self;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableArray<NSDictionary<NSString *, id> *> *mainItems = [NSMutableArray array];
        NSMutableArray<NSDictionary<NSString *, id> *> *thirdItems = [NSMutableArray array];
        NSMutableArray<NSDictionary<NSString *, id> *> *systemItems = [NSMutableArray array];
        NSMutableArray<NSDictionary<NSString *, id> *> *sections = [NSMutableArray array];

        __block NSString *failure = nil;
        __block BOOL truncated = NO;

        if (!kexploit_krw_ready()) {
            failure = @"内核读写尚未就绪，无法附加到目标进程。";
        } else if (name.length == 0) {
            failure = @"进程名为空。";
        } else {
            // 目标挂起时不要让界面等两分钟：每次尝试 12s，最多三次。
            void (^hint)(NSString *) = ^(NSString *text) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    __strong typeof(weakSelf) strongSelf = weakSelf;
                    if (!strongSelf) return;
                    strongSelf.loadingHintText = text;
                    [strongSelf refreshPlaceholderState];
                });
            };

            RemoteCallSession *session = cyanide_attach_to_process(name, procAddr, 12000, hint);

            if (!session) {
                RemoteCallInitFailure reason = remote_call_last_init_failure();
                const char *desc = (reason != RemoteCallInitFailureNone)
                    ? remote_call_init_failure_description(reason) : NULL;
                NSString *reasonText = desc ? [NSString stringWithUTF8String:desc] : @"未知原因";
                failure = [NSString stringWithFormat:
                           @"无法附加到 %@（%@）。\n"
                           @"目标 App 被系统挂起时没有运行中的线程，异常端口劫持必然超时；"
                           @"SpringBoard 这类常驻进程一般可以成功。",
                           name, reasonText];
            } else {
                uint64_t count = [session doRemoteCallStableWithTimeout:8000
                                                          functionName:"_dyld_image_count"
                                                                    x0:0 x1:0 x2:0 x3:0
                                                                    x4:0 x5:0 x6:0 x7:0];
                cyanide_log(@"[库] 目标=%@ 模块数=%llu", name, count);
                if (count == 0) {
                    failure = @"目标进程没有报告任何库（_dyld_image_count 返回 0）。";
                } else if (count > kModuleCountLimit) {
                    failure = [NSString stringWithFormat:@"库数量异常（%llu），已放弃读取。",
                               (unsigned long long)count];
                } else {
                    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + kModuleLoadDeadline;

                    for (uint64_t i = 0; i < count; i++) {
                        if (CFAbsoluteTimeGetCurrent() > deadline) {
                            truncated = YES;
                            break;
                        }

                        uint64_t base = [session doRemoteCallStableWithTimeout:8000
                                                                 functionName:"_dyld_get_image_header"
                                                                           x0:i x1:0 x2:0 x3:0
                                                                           x4:0 x5:0 x6:0 x7:0];

                        uint64_t namePtr = [session doRemoteCallStableWithTimeout:8000
                                                                    functionName:"_dyld_get_image_name"
                                                                              x0:i x1:0 x2:0 x3:0
                                                                              x4:0 x5:0 x6:0 x7:0];

                        char pathBuffer[1024] = {0};
                        if (namePtr != 0) {
                            [session remoteRead:namePtr to:pathBuffer size:sizeof(pathBuffer) - 1];
                        }

                        NSString *path = [NSString stringWithUTF8String:pathBuffer];
                        if (path.length == 0) path = @"";

                        NSString *display = path.lastPathComponent;
                        if (display.length == 0) {
                            display = path.length > 0 ? path : @"（未知库）";
                        }

                        NSDictionary *item = @{
                            @"name": display,
                            @"path": path,
                            @"base": @(base),
                        };

                        if (i == 0) {
                            [mainItems addObject:item];
                        } else if (module_path_is_third_party(path)) {
                            [thirdItems addObject:item];
                        } else {
                            [systemItems addObject:item];
                        }
                    }
                }
            }
            // session 由 ARC 释放，dealloc 里会收掉目标线程。
        }

        cyanide_log(@"[库] 读取结束 主程序=%lu 第三方=%lu 系统=%lu 截断=%d",
             (unsigned long)mainItems.count, (unsigned long)thirdItems.count,
             (unsigned long)systemItems.count, truncated ? 1 : 0);

        if (mainItems.count > 0) {
            [sections addObject:@{@"kind": kGroupKindMain, @"title": @"主程序", @"items": mainItems}];
        }
        if (thirdItems.count > 0) {
            [sections addObject:@{@"kind": kGroupKindThird, @"title": @"第三方库", @"items": thirdItems}];
        }
        if (systemItems.count > 0) {
            [sections addObject:@{@"kind": kGroupKindSystem, @"title": @"系统库", @"items": systemItems}];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;

            self.sections = sections;
            self.truncated = truncated;
            if (failure.length > 0) {
                self.state = ModuleListStateFailed;
                self.failureReason = failure;
            } else {
                self.state = ModuleListStateLoaded;
            }
            [self refreshPlaceholderState];
            [self.tableView reloadData];
        });
    });
}

#pragma mark - 数据访问

- (NSArray<NSDictionary<NSString *, id> *> *)itemsInSection:(NSInteger)section
{
    if (section < 0 || section >= (NSInteger)self.sections.count) return @[];
    return self.sections[(NSUInteger)section][@"items"];
}

- (NSDictionary<NSString *, id> *)itemAtIndexPath:(NSIndexPath *)indexPath
{
    NSArray<NSDictionary<NSString *, id> *> *items = [self itemsInSection:indexPath.section];
    if (indexPath.row < 0 || indexPath.row >= (NSInteger)items.count) return nil;
    return items[(NSUInteger)indexPath.row];
}

#pragma mark - UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return (NSInteger)self.sections.count;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return (NSInteger)[self itemsInSection:section].count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if (section < 0 || section >= (NSInteger)self.sections.count) return nil;
    NSDictionary<NSString *, id> *sec = self.sections[(NSUInteger)section];
    return [NSString stringWithFormat:@"%@（%lu）",
            sec[@"title"], (unsigned long)[sec[@"items"] count]];
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    if (self.sections.count == 0) return nil;
    if (section != (NSInteger)self.sections.count - 1) return nil;

    NSUInteger third = 0;
    NSUInteger system = 0;
    NSUInteger total = 0;
    for (NSDictionary<NSString *, id> *sec in self.sections) {
        NSUInteger n = [sec[@"items"] count];
        total += n;
        if ([sec[@"kind"] isEqualToString:kGroupKindThird]) third = n;
        if ([sec[@"kind"] isEqualToString:kGroupKindSystem]) system = n;
    }

    NSMutableString *text = [NSMutableString stringWithFormat:
        @"共 %lu 项（第三方库 %lu · 系统库 %lu）。基址是该库 mach_header 在目标进程里的实际加载地址（含 ASLR 偏移）。点按一行可复制。",
        (unsigned long)total, (unsigned long)third, (unsigned long)system];
    if (self.truncated) {
        [text appendString:@"\n读取超时，结果不完整。"];
    }
    return text;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kModuleCellIdentifier];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:kModuleCellIdentifier];
        cell.textLabel.font = [UIFont systemFontOfSize:15.0 weight:UIFontWeightMedium];
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
        cell.detailTextLabel.numberOfLines = 2;
        cell.detailTextLabel.font = [UIFont monospacedDigitSystemFontOfSize:11.0
                                                                     weight:UIFontWeightRegular];
    }

    NSDictionary<NSString *, id> *row = [self itemAtIndexPath:indexPath];
    uint64_t base = [row[@"base"] unsignedLongLongValue];
    NSString *path = row[@"path"];

    cell.textLabel.text = row[@"name"];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"0x%llx%@",
                                 (unsigned long long)base,
                                 path.length > 0 ? [@"\n" stringByAppendingString:path] : @""];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    NSDictionary<NSString *, id> *row = [self itemAtIndexPath:indexPath];
    if (!row) return;

    NSString *name = row[@"name"];
    NSString *path = row[@"path"];
    uint64_t base = [row[@"base"] unsignedLongLongValue];

    NSString *message = [NSString stringWithFormat:@"基址 0x%llx\n%@",
                         (unsigned long long)base, path ?: @""];

    UIAlertController *sheet =
        [UIAlertController alertControllerWithTitle:name
                                            message:message
                                     preferredStyle:UIAlertControllerStyleActionSheet];

    [sheet addAction:[UIAlertAction actionWithTitle:@"复制基址与路径"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [UIPasteboard generalPasteboard].string =
            [NSString stringWithFormat:@"%@ 0x%llx %@", name, (unsigned long long)base, path ?: @""];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"Dump 这个模块到文件"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [self dumpModuleAtPath:path displayName:name];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];

    // iPad 上 action sheet 需要锚点，否则会崩。
    sheet.popoverPresentationController.sourceView = tableView;
    sheet.popoverPresentationController.sourceRect = [tableView rectForRowAtIndexPath:indexPath];

    [self presentViewController:sheet animated:YES completion:nil];
}

#pragma mark - 后台监听

// 关掉页面时停止监听。
- (void)dealloc
{
    if (self.watchTimer) {
        dispatch_source_cancel(self.watchTimer);
        self.watchTimer = nil;
    }
}

- (void)toggleBackgroundWatch
{
    if (self.watching) {
        [self stopBackgroundWatch];
        [self presentAlertWithTitle:@"已停止后台监听" message:nil];
        return;
    }

    if (!kexploit_krw_ready()) {
        [self presentAlertWithTitle:@"内核未就绪"
                            message:@"请先回到「进程」页初始化内核。"];
        return;
    }

    self.watching = YES;
    self.watchAttempt = 0;
    self.navigationItem.rightBarButtonItem.title = @"停止监听";

    // 切到目标 App 后本进程要活着才能继续重试。
    ds_keepalive_apply_enabled(YES);

    if (!self.watchQueue) {
        self.watchQueue = dispatch_queue_create("com.cyanide.watchattach", DISPATCH_QUEUE_SERIAL);
    }

    __weak typeof(self) weakSelf = self;
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.watchQueue);
    dispatch_source_set_timer(timer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                              (uint64_t)(2.0 * NSEC_PER_SEC),
                              (uint64_t)(0.3 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(timer, ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self || !self.watching) return;
        [self watchTick];
    });
    dispatch_resume(timer);
    self.watchTimer = timer;

    cyanide_log(@"[监听] 开始后台监听 %@（每 2 秒重试一次附加，超时 1.5 秒）", self.processName);

    [self presentAlertWithTitle:@"已开始后台监听"
                        message:[NSString stringWithFormat:
                                 @"现在切到 %@ 并让它跑起来。\n\n"
                                 @"游戏在前台运行时，这里每 2 秒会试一次附加，成功后自动读取库列表并写入文件。\n\n"
                                 @"玩一会儿再回 Cyanide 看「日志」即可。", self.processName]];
}

- (void)stopBackgroundWatch
{
    self.watching = NO;
    self.navigationItem.rightBarButtonItem.title = @"后台监听";

    if (self.watchTimer) {
        dispatch_source_cancel(self.watchTimer);
        self.watchTimer = nil;
    }
}

- (void)watchTick
{
    if (!self.watching) return;

    self.watchAttempt += 1;
    NSUInteger attempt = self.watchAttempt;

    // 目标被挂起时每次都要等满超时，所以这里用短超时（1.5s），
    // 保证 2 秒一次的重试节奏不会被拖垮。
    RemoteCallSession *session = cyanide_attach_to_process(self.processName, self.procAddr, 1500, nil);
    if (!session) {
        if (attempt % 10 == 1) {
            cyanide_log(@"[监听] 第 %lu 次尝试：目标还没在运行（附加超时属正常，继续等）",
                        (unsigned long)attempt);
        }
        return;
    }

    cyanide_log(@"[监听] 第 %lu 次尝试：附加成功，开始读取库列表", (unsigned long)attempt);

    NSString *report = [self buildLibraryReportWithSession:session];
    if (report.length == 0) {
        cyanide_log(@"[监听] 附加成功但没读到模块（dyld 返回 0）");
        return;
    }

    NSString *documents =
        NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *dumpDir = [documents stringByAppendingPathComponent:@"dumps"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dumpDir
                             withIntermediateDirectories:YES
                                              attributes:nil
                                                   error:NULL];

    NSDateFormatter *stamp = [[NSDateFormatter alloc] init];
    stamp.dateFormat = @"yyyyMMdd-HHmmss";
    NSString *fileName = [NSString stringWithFormat:@"%@-库列表-%@.txt",
                          self.processName ?: @"proc", [stamp stringFromDate:[NSDate date]]];
    NSString *path = [dumpDir stringByAppendingPathComponent:fileName];

    NSError *error = nil;
    BOOL wrote = [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error];
    cyanide_log(@"[监听] 写入报告 %@ -> %d %@", fileName, wrote ? 1 : 0, error.localizedDescription ?: @"");

    dispatch_async(dispatch_get_main_queue(), ^{
        [self stopBackgroundWatch];
        [self presentAlertWithTitle:@"后台监听成功"
                            message:[NSString stringWithFormat:
                                     @"已读取 %@ 的库列表并保存：\n\n%@\n\n"
                                     @"（「文件」App → 我的 iPhone → Cyanide → dumps 里可取）",
                                     self.processName, fileName]];
    });
}

// 把模块列表拼成纯文本报告（不依赖界面）。
- (NSString *)buildLibraryReportWithSession:(RemoteCallSession *)session
{
    NSMutableString *report = [NSMutableString string];
    [report appendFormat:@"进程：%@ (PID %d)\n", self.processName, self.pid];

    NSMutableArray<NSString *> *mainLines = [NSMutableArray array];
    NSMutableArray<NSString *> *thirdLines = [NSMutableArray array];
    NSMutableArray<NSString *> *systemLines = [NSMutableArray array];

    __block NSUInteger total = 0;
    __block BOOL truncated = NO;

    remote_call_with_session(session, ^{
        uint64_t count = r_dlsym_call(2, "_dyld_image_count", 0, 0, 0, 0, 0, 0, 0, 0);
        if (count == 0 || count > 4096) return;

        CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 15.0;

        for (uint64_t i = 0; i < count; i++) {
            if (CFAbsoluteTimeGetCurrent() > deadline) {
                truncated = YES;
                break;
            }

            uint64_t base = r_dlsym_call(2, "_dyld_get_image_header", i, 0, 0, 0, 0, 0, 0, 0);
            uint64_t namePtr = r_dlsym_call(2, "_dyld_get_image_name", i, 0, 0, 0, 0, 0, 0, 0);

            char buffer[512] = {0};
            if (namePtr != 0) {
                remote_read(namePtr, buffer, sizeof(buffer) - 1);
            }

            NSString *path = [NSString stringWithUTF8String:buffer];
            if (path.length == 0) path = @"";

            NSString *line = [NSString stringWithFormat:@"  0x%llx %@",
                              (unsigned long long)base, path];

            total += 1;
            if (i == 0) {
                [mainLines addObject:line];
            } else if (module_path_is_third_party(path)) {
                [thirdLines addObject:line];
            } else {
                [systemLines addObject:line];
            }
        }
    });

    if (total == 0) return @"";

    [report appendFormat:@"共 %lu 项（第三方 %lu · 系统 %lu）%@\n\n",
     (unsigned long)total, (unsigned long)thirdLines.count, (unsigned long)systemLines.count,
     truncated ? @"［超时，不完整］" : @""];

    if (mainLines.count > 0) {
        [report appendString:@"== 主程序 ==\n"];
        for (NSString *line in mainLines) [report appendFormat:@"%@\n", line];
        [report appendString:@"\n"];
    }
    if (thirdLines.count > 0) {
        [report appendString:@"== 第三方库 ==\n"];
        for (NSString *line in thirdLines) [report appendFormat:@"%@\n", line];
        [report appendString:@"\n"];
    }
    if (systemLines.count > 0) {
        [report appendString:@"== 系统库 ==\n"];
        for (NSString *line in systemLines) [report appendFormat:@"%@\n", line];
    }

    return report;
}

#pragma mark - Dump 模块

// 从磁盘把模块文件复制到 App 沙盒的 Documents/dumps/。
// 不走目标进程内存：目标挂起、甚至已经退出，都能拿到完整文件。
- (void)dumpModuleAtPath:(NSString *)sourcePath displayName:(NSString *)displayName
{
    if (sourcePath.length == 0) {
        [self presentAlertWithTitle:@"无法 dump" message:@"这个模块没有可用的路径。"];
        return;
    }

    [self presentBusyAlertWithTitle:@"正在 dump…" message:displayName];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *resultTitle = nil;
        NSString *resultMessage = nil;

        if (!kexploit_krw_ready()) {
            cyanide_log(@"[Dump] 中止：内核未就绪");
            resultTitle = @"内核未就绪";
            resultMessage = @"请先回到「进程」页初始化内核。";
        } else if (!cyanide_ensure_file_access()) {
            resultTitle = @"无法读取该路径";
            resultMessage = @"沙盒逃逸失败，读不到目标 App 的文件。";
        } else {
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                                      NSUserDomainMask, YES).firstObject;
            NSString *dumpDir = [documents stringByAppendingPathComponent:@"dumps"];
            [fm createDirectoryAtPath:dumpDir withIntermediateDirectories:YES attributes:nil error:NULL];

            NSDateFormatter *stamp = [[NSDateFormatter alloc] init];
            stamp.dateFormat = @"yyyyMMdd-HHmmss";
            NSString *fileName = [NSString stringWithFormat:@"%@-%@-%@",
                                  self.processName ?: @"proc",
                                  displayName ?: @"module",
                                  [stamp stringFromDate:[NSDate date]]];
            fileName = [fileName stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
            NSString *destPath = [dumpDir stringByAppendingPathComponent:fileName];

            cyanide_log(@"[Dump] 源文件=%@", sourcePath);
            cyanide_log(@"[Dump] 目标文件=%@", destPath);

            CFAbsoluteTime copyStart = CFAbsoluteTimeGetCurrent();
            NSError *error = nil;
            BOOL copied = [fm copyItemAtPath:sourcePath toPath:destPath error:&error];
            cyanide_log(@"[Dump] 复制结果=%d 耗时=%.0fms 错误=%@",
                 copied ? 1 : 0, (CFAbsoluteTimeGetCurrent() - copyStart) * 1000.0,
                 error.localizedDescription ?: @"无");

            if (copied) {
                NSDictionary *attrs = [fm attributesOfItemAtPath:destPath error:NULL];
                unsigned long long size = [attrs fileSize];
                resultTitle = @"Dump 完成";
                resultMessage = [NSString stringWithFormat:@"%@\n\n%.2f MB\n\n%@",
                                 fileName, (double)size / (1024.0 * 1024.0), destPath];
            } else {
                resultTitle = @"Dump 失败";
                resultMessage = error.localizedDescription ?: @"未知错误";
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self dismissViewControllerAnimated:YES completion:^{
                [self presentAlertWithTitle:resultTitle message:resultMessage];
            }];
        });
    });
}

- (void)presentBusyAlertWithTitle:(NSString *)title message:(NSString *)message
{
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:title
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
