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

// 每个元素：@{@"kind": 分组标识, @"title": 分组标题, @"items": @[ @{name,path,base} ]}
@property (nonatomic, copy) NSArray<NSDictionary<NSString *, id> *> *sections;
@property (nonatomic, assign) ModuleListState state;
@property (nonatomic, copy) NSString *failureReason;
@property (nonatomic, assign) BOOL truncated;

@property (nonatomic, strong) UIView *placeholderView;
@property (nonatomic, strong) UILabel *placeholderLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;

@end

@implementation ProcessDetailViewController

- (instancetype)initWithProcessName:(NSString *)processName pid:(int)pid
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _processName = [processName copy];
        _pid = pid;
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = self.processName.length > 0 ? self.processName : @"库";
    self.tableView.rowHeight = 62.0;

    [self buildPlaceholderView];
    [self loadModules];
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
            self.placeholderLabel.text = [NSString stringWithFormat:
                @"正在附加到 %@ (PID %d) 并读取库列表…\n首次附加可能要几秒。",
                self.processName, self.pid];
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
    [self refreshPlaceholderState];

    NSString *name = [self.processName copy];
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
            // 15s 而不是默认的 120s：目标挂起时不要让界面等两分钟。
            RemoteCallSession *session =
                [[RemoteCallSession alloc] initWithProcess:name
                                        useMigFilterBypass:NO
                                   firstExceptionTimeoutMS:15000];

            if (!session) {
                failure = [NSString stringWithFormat:
                           @"无法附加到 %@。\n可能是目标已挂起、正在退出，或系统不允许创建远程线程。",
                           name];
            } else {
                uint64_t count = [session doRemoteCallStableWithTimeout:8000
                                                          functionName:"_dyld_image_count"
                                                                    x0:0 x1:0 x2:0 x3:0
                                                                    x4:0 x5:0 x6:0 x7:0];
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

    uint64_t base = [row[@"base"] unsignedLongLongValue];
    NSString *copy = [NSString stringWithFormat:@"%@ 0x%llx %@",
                      row[@"name"], (unsigned long long)base, row[@"path"] ?: @""];
    [UIPasteboard generalPasteboard].string = copy;

    UIImpactFeedbackGenerator *feedback =
        [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
    [feedback impactOccurred];
}

@end
