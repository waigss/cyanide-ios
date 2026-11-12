//
//  ProcessListViewController.m
//  Cyanide
//
//  「进程」页。数据来源是内核里 struct proc 的 p_list 双向链表（经 kread 读取），
//  不是 sysctl(KERN_PROC_ALL) —— 后者对非特权 app 一律返回 EPERM，即使打完沙盒
//  补丁也一样。
//
//  读取整张表要上千次 kread，所以放在后台队列跑，完成后回主线程刷新界面。
//  本页只读，不改任何内核状态；唯一会写内核的动作是用户主动点「初始化内核」，
//  那一条走的是 App 现有的 settings_run_actions()（等同设置页的 Apply Tweaks）。
//

#import "ProcessListViewController.h"

#import "ProcessDetailViewController.h"
#import "CyanideLog.h"
#import "LogViewerController.h"

#import <string.h>

#import "../kexploit/kutils.h"
#import "../kexploit/krw.h"
#import "../kexploit/offsets.h"
#import "../kexploit/xpaci.h"
#import "../kexploit/kexploit_opa334.h"
#import "../SettingsViewController.h"

static NSString * const kProcessCellIdentifier = @"CyanideProcessCell";
static const int kProcessCapacity = 1024;
static const NSTimeInterval kInitTimeout = 240.0;

@interface ProcessListViewController () <UISearchResultsUpdating>

@property (nonatomic, strong) UISearchController *searchController;
@property (nonatomic, copy) NSArray<NSDictionary<NSString *, id> *> *allProcesses;
@property (nonatomic, copy) NSArray<NSDictionary<NSString *, id> *> *visibleProcesses;

@property (nonatomic, strong) UIView *placeholderView;
@property (nonatomic, strong) UILabel *placeholderLabel;
@property (nonatomic, strong) UIButton *kernelInitButton;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;

@property (nonatomic, assign) BOOL loading;
@property (nonatomic, assign) BOOL initializing;
@property (nonatomic, assign) BOOL lastInitFailed;
@property (nonatomic, assign) NSUInteger kernelInitToken;


@end

@implementation ProcessListViewController

#pragma mark - 内核只读探测（定位 pmap 偏移用）

// 只读：把我们自己进程的 task / vm_map 结构前若干字节原样打进日志。
// 全部读取都发生在已知已分配的内核结构内部，不写任何数据。
- (void)confirmKernelProbe
{
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:@"内核只读探测"
                                            message:@"将把本进程的 task / vm_map 结构前几百字节写入日志，"
                                                    @"用于定位 pmap 字段偏移。\n\n"
                                                    @"只读取内核结构，不写入任何数据，也不会改动系统状态。\n\n"
                                                    @"日志里会出现 [PMAP] 开头的十六进制行，请把它们发回分析。"
                                     preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"开始探测"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [self performKernelProbe];
    }]];

    [self presentViewController:alert animated:YES completion:nil];
}

// 自校验用的已知内容：地址和字节都确定，用来核对页表翻译。
static const char kPmapSelfTest[] = "CYANIDE_PMAP_SELFTEST_0123456789";

- (void)performKernelProbe
{
    if (!kexploit_krw_ready()) {
        cyanide_log(@"[PMAP] 探测中止：内核未就绪");
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        cyanide_log_sync(@"[PMAP] ==== 诊断 v8：三级页表遍历 + 自校验 ====");

        uint64_t selfProc = proc_self();
        uint64_t task = proc_task(selfProc);
        uint64_t map = task ? kread_ptr(task + off_task_map) : 0;
        if (!is_kaddr_valid(map)) {
            cyanide_log_sync(@"[PMAP] map 无效，停止");
            return;
        }

        uint64_t pmap = kread_ptr(map + 0x40);
        if (!is_kaddr_valid(pmap)) {
            cyanide_log_sync(@"[PMAP] pmap 无效，停止");
            return;
        }

        uint64_t tte = kread_ptr(pmap + 0x00);
        uint64_t ttep = kread64(pmap + 0x08);
        if (!is_kaddr_valid(tte) || ttep == 0) {
            cyanide_log_sync(@"[PMAP] tte/ttep 不可用，停止");
            return;
        }

        const uint64_t windowOffset = tte - ttep;
        cyanide_log_sync(@"[PMAP] tte=0x%llx ttep=0x%llx 窗口偏移=0x%llx",
                        tte, ttep, windowOffset);

        const uint64_t va = (uint64_t)(uintptr_t)kPmapSelfTest;
        const uint64_t pageMask = 0x3FFFULL;      // 16KB 页
        // arm64 页表项：bit[47:14] 才是输出物理地址，高位是属性/软件标志位
        const uint64_t paMask = 0x0000FFFFFFFFC000ULL;
        const uint64_t inPageOffset = va & pageMask;

        cyanide_log_sync(@"[PMAP] 被测 VA=0x%llx 页内偏移=0x%llx", va, inPageOffset);

        // ---- L0 ----
        uint64_t l0Index = (va >> 36) & 0xFFFULL;
        uint64_t e0 = kread64(tte + l0Index * 8);
        cyanide_log_sync(@"[PMAP] L0[%llu]=0x%016llx", l0Index, e0);
        if ((e0 & 1) == 0) {
            cyanide_log_sync(@"[PMAP] L0 项无效，停止");
            return;
        }

        // ---- L1 ----
        uint64_t l1Kva = (e0 & paMask) + windowOffset;
        cyanide_log_sync(@"[PMAP] L1 物理=0x%llx L1 KVA=0x%llx", e0 & paMask, l1Kva);

        uint64_t l1Index = (va >> 25) & 0x7FFULL;
        uint64_t e1 = kread64(l1Kva + l1Index * 8);
        cyanide_log_sync(@"[PMAP] L1[%llu]=0x%016llx", l1Index, e1);
        if ((e1 & 1) == 0) {
            cyanide_log_sync(@"[PMAP] L1 项无效，停止");
            return;
        }

        // ---- L2 ----
        uint64_t l2Kva = (e1 & paMask) + windowOffset;
        cyanide_log_sync(@"[PMAP] L2 物理=0x%llx L2 KVA=0x%llx", e1 & paMask, l2Kva);

        uint64_t l2Index = (va >> 14) & 0x7FFULL;
        uint64_t e2 = kread64(l2Kva + l2Index * 8);
        cyanide_log_sync(@"[PMAP] L2[%llu]=0x%016llx", l2Index, e2);
        if ((e2 & 1) == 0) {
            cyanide_log_sync(@"[PMAP] L2 项无效，停止");
            return;
        }

        // ---- 数据页 ----
        uint64_t dataPagePa = e2 & paMask;
        uint64_t dataKva = dataPagePa + windowOffset + inPageOffset;
        cyanide_log_sync(@"[PMAP] 数据页物理=0x%llx 读取地址=0x%llx", dataPagePa, dataKva);

        char buffer[96] = {0};
        kreadbuf(dataKva, buffer, sizeof(kPmapSelfTest));
        cyanide_log_sync(@"[PMAP] 读回=\"%s\"", buffer);

        BOOL match = (memcmp(buffer, kPmapSelfTest, sizeof(kPmapSelfTest)) == 0);
        cyanide_log_sync(@"[PMAP] 自校验%@", match ? @"通过 ✅ 跨进程读内存打通" : @"失败 ❌");

        cyanide_log_sync(@"[PMAP] ==== 诊断结束 ====");
    });
}

// 只读一段已知结构，逐 8 字节打印 raw / xpaci 两种形态并做标注。
// 不会解引用这里读到的任何值。
- (void)logPointerWordsAt:(uint64_t)addr length:(NSUInteger)length label:(NSString *)label
{
    if (addr == 0 || !is_kaddr_valid(addr)) {
        cyanide_log(@"[PMAP] %@ 地址无效：0x%llx", label, addr);
        return;
    }

    for (NSUInteger off = 0; off < length; off += 8) {
        uint64_t raw = kread64(addr + off);
        uint64_t pac = xpaci(raw);

        NSString *mark = @"";
        if (!is_kaddr_valid(raw) && is_kaddr_valid(pac)) {
            mark = @"  <- PAC 签名指针";
        } else if (is_kaddr_valid(raw)) {
            mark = @"  <- 明文指针";
        }

        cyanide_log(@"[PMAP] %@+0x%03lx raw=0x%016llx xpaci=0x%016llx%@",
                    label, (unsigned long)off, raw, pac, mark);
    }
}

- (void)dumpWordsAt:(uint64_t)addr length:(NSUInteger)length label:(NSString *)label
{
    if (addr == 0 || !is_kaddr_valid(addr)) {
        cyanide_log(@"[PMAP] %@ 地址无效：0x%llx", label, addr);
        return;
    }

    NSMutableData *data = [NSMutableData dataWithLength:length];
    if (!data) return;

    kreadbuf(addr, data.mutableBytes, (uint64_t)length);

    const uint64_t *words = (const uint64_t *)data.bytes;
    NSUInteger count = length / 8;
    for (NSUInteger i = 0; i < count; i++) {
        cyanide_log(@"[PMAP] %@+0x%03lx = 0x%016llx", label, (unsigned long)(i * 8), words[i]);
    }
}

- (void)showLog
{
    LogViewerController *log = [[LogViewerController alloc] init];
    [self.navigationController pushViewController:log animated:YES];
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = @"进程";
    self.tableView.rowHeight = 58.0;
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;

    UIRefreshControl *refresh = [[UIRefreshControl alloc] init];
    refresh.tintColor = [UIColor systemBlueColor];
    [refresh addTarget:self
                action:@selector(reloadProcesses)
      forControlEvents:UIControlEventValueChanged];
    self.refreshControl = refresh;

    UISearchController *search = [[UISearchController alloc] initWithSearchResultsController:nil];
    search.searchResultsUpdater = self;
    search.obscuresBackgroundDuringPresentation = NO;
    search.searchBar.placeholder = @"搜索进程名或 PID";
    search.searchBar.tintColor = [UIColor systemBlueColor];
    self.navigationItem.searchController = search;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.searchController = search;
    self.definesPresentationContext = YES;

    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                      target:self
                                                      action:@selector(reloadProcesses)],
        [[UIBarButtonItem alloc] initWithTitle:@"日志"
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(showLog)],
        [[UIBarButtonItem alloc] initWithTitle:@"探测"
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(confirmKernelProbe)],
    ];

    [self buildPlaceholderView];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(actionsDidComplete:)
                                                 name:kSettingsActionsDidCompleteNotification
                                               object:nil];

    [self reloadProcesses];
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];

    // 从别处初始化完内核再回来时，自动补一次读取。
    if (!self.initializing && kexploit_krw_ready() && self.allProcesses.count == 0) {
        [self reloadProcesses];
    }
}

#pragma mark - 空状态 / 初始化入口

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

    self.kernelInitButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.kernelInitButton setTitle:@"初始化内核" forState:UIControlStateNormal];
    self.kernelInitButton.titleLabel.font = [UIFont systemFontOfSize:17.0 weight:UIFontWeightSemibold];
    [self.kernelInitButton addTarget:self
                        action:@selector(startKernelInit)
              forControlEvents:UIControlEventTouchUpInside];

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.spinner, self.placeholderLabel, self.kernelInitButton
    ]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentFill;
    stack.spacing = 18.0;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [container addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:container.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:container.centerYAnchor],
        [stack.widthAnchor   constraintLessThanOrEqualToConstant:320.0],
        [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:container.leadingAnchor constant:16.0],
        [self.kernelInitButton.heightAnchor constraintEqualToConstant:44.0],
    ]];

    self.placeholderView = container;
    self.tableView.backgroundView = container;
}

// 按当前状态决定空状态里显示什么、有没有按钮。
- (void)refreshPlaceholderState
{
    if (self.visibleProcesses.count > 0) {
        self.tableView.backgroundView = nil;
        [self.spinner stopAnimating];
        return;
    }

    self.tableView.backgroundView = self.placeholderView;

    BOOL showButton = NO;
    BOOL spinning = NO;
    NSString *text = nil;

    if (self.initializing) {
        text = @"正在初始化内核…\n这一步可能要几十秒，请保持本页在前台。";
        spinning = YES;
    } else if (!settings_device_supported()) {
        text = [NSString stringWithFormat:
                @"当前系统不支持，无法初始化内核。\n仅支持 iOS 17.0–18.7.1 或 26.0–26.0.1，当前为 iOS %@。",
                UIDevice.currentDevice.systemVersion ?: @"未知"];
    } else if (!kexploit_krw_ready()) {
        if (self.lastInitFailed) {
            text = @"初始化没有成功，具体原因见「Log」页。\n可以再点一次重试。";
        } else {
            text = @"内核尚未初始化。\n点下面的按钮开始初始化，成功后本页会自动刷新。";
        }
        showButton = YES;
    } else if (self.searchController.searchBar.text.length > 0) {
        text = [NSString stringWithFormat:@"没有匹配「%@」的进程",
                self.searchController.searchBar.text];
    } else if ([self uidProbeUsable]) {
        text = @"当前没有正在运行的应用进程。";
    } else {
        text = @"没有读取到进程";
    }

    self.placeholderLabel.text = text;
    self.kernelInitButton.hidden = !showButton;
    self.kernelInitButton.enabled = showButton;
    if (spinning) {
        [self.spinner startAnimating];
    } else {
        [self.spinner stopAnimating];
    }
}

- (void)startKernelInit
{
    if (self.initializing) return;

    if (!settings_device_supported()) {
        self.lastInitFailed = NO;
        [self refreshPlaceholderState];
        return;
    }

    self.initializing = YES;
    self.lastInitFailed = NO;

    cyanide_log(@"[内核] 开始初始化：krw_ready=%d", kexploit_krw_ready() ? 1 : 0);
    CFAbsoluteTime initStart = CFAbsoluteTimeGetCurrent();
    self.kernelInitToken += 1;
    NSUInteger token = self.kernelInitToken;
    [self refreshPlaceholderState];

    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kInitTimeout * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self || !self.initializing || self.kernelInitToken != token) return;
        self.initializing = NO;
        self.lastInitFailed = YES;
        [self refreshPlaceholderState];
    });

    // settings_run_actions() 内部自己起后台队列，这里只是触发；
    // 完成后会给 kSettingsActionsDidCompleteNotification。
    settings_run_actions();
    cyanide_log(@"[内核] 已下发初始化请求（settings_run_actions）");
}

- (void)actionsDidComplete:(NSNotification *)note
{
    BOOL ok = [note.userInfo[kSettingsActionsDidCompleteSuccessKey] boolValue];
    cyanide_log(@"[内核] 初始化回调 成功=%d krw_ready=%d self_proc=0x%llx",
         ok ? 1 : 0, kexploit_krw_ready() ? 1 : 0, proc_self());
    if (self.initializing) {
        self.initializing = NO;
        self.lastInitFailed = !ok;
    }
    [self reloadProcesses];
}

#pragma mark - 读取

- (void)reloadProcesses
{
    if (self.loading) return;
    self.loading = YES;

    if (self.allProcesses.count == 0) {
        [self refreshPlaceholderState];
    }

    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray<NSDictionary<NSString *, id> *> *rows = [weakSelf snapshotProcesses];
        dispatch_async(dispatch_get_main_queue(), ^{
            __strong typeof(weakSelf) self = weakSelf;
            if (!self) return;
            self.loading = NO;
            self.allProcesses = rows;
            [self applyFilter];
            [self.refreshControl endRefreshing];
        });
    });
}

// 在内核里走一遍 proc 链表并拷贝成普通对象，调用方负责放到后台线程。
- (NSArray<NSDictionary<NSString *, id> *> *)snapshotProcesses
{
    if (!kexploit_krw_ready()) {
        return @[];
    }

    proc_entry_t *buffer = calloc((size_t)kProcessCapacity, sizeof(proc_entry_t));
    if (!buffer) return @[];

    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    uint64_t selfProc = proc_self();
    int count = proc_list_all(buffer, kProcessCapacity);
    cyanide_log(@"[进程表] self_proc=0x%llx 读取到 %d 个进程 耗时=%.0fms",
         selfProc, count, (CFAbsoluteTimeGetCurrent() - t0) * 1000.0);
    if (count <= 0) {
        cyanide_log(@"[进程表] 读取为空：krw_ready=%d self_proc=0x%llx（若 self_proc 为 0，说明内核会话没真正建立）",
             kexploit_krw_ready() ? 1 : 0, selfProc);
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *rows =
        [NSMutableArray arrayWithCapacity:(NSUInteger)MAX(count, 0)];

    for (int i = 0; i < count; i++) {
        NSString *name = [NSString stringWithUTF8String:buffer[i].name];
        if (name.length == 0) name = @"（未命名）";
        [rows addObject:@{
            @"name": name,
            @"pid":  @(buffer[i].pid),
            @"uid":  @(buffer[i].uid),
            @"proc": @(buffer[i].proc),
        }];
    }

    free(buffer);

    [rows sortUsingComparator:^NSComparisonResult(NSDictionary<NSString *, id> *a,
                                                 NSDictionary<NSString *, id> *b) {
        return [a[@"pid"] compare:b[@"pid"]];
    }];

    return rows;
}

#pragma mark - 过滤与刷新

// UID 探测失败时（所有项都是 UINT32_MAX）不要因为过滤把列表清空，
// 这种情况直接退化成「显示全部」。
- (BOOL)uidProbeUsable
{
    for (NSDictionary<NSString *, id> *row in self.allProcesses) {
        if ([row[@"uid"] unsignedIntValue] != UINT32_MAX) return YES;
    }
    return NO;
}

- (void)applyFilter
{
    NSString *query = self.searchController.searchBar.text ?: @"";
    query = [query stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    BOOL appsOnly = [self uidProbeUsable];

    NSMutableArray<NSDictionary<NSString *, id> *> *filtered = [NSMutableArray array];
    for (NSDictionary<NSString *, id> *row in self.allProcesses) {
        if (appsOnly && [row[@"uid"] unsignedIntValue] != 501) continue;

        if (query.length == 0) {
            [filtered addObject:row];
            continue;
        }
        NSString *name = row[@"name"];
        NSString *pid = [row[@"pid"] stringValue];
        BOOL nameHit = [name rangeOfString:query options:NSCaseInsensitiveSearch].location != NSNotFound;
        BOOL pidHit = [pid rangeOfString:query].location != NSNotFound;
        if (nameHit || pidHit) {
            [filtered addObject:row];
        }
    }

    self.visibleProcesses = filtered;
    [self refreshPlaceholderState];
    [self.tableView reloadData];
}

#pragma mark - UITableViewDataSource

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return (NSInteger)self.visibleProcesses.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if (self.visibleProcesses.count == 0) return nil;

    BOOL appsOnly = [self uidProbeUsable];
    if (appsOnly) {
        return [NSString stringWithFormat:@"共 %lu 个应用进程",
                (unsigned long)self.visibleProcesses.count];
    }
    return [NSString stringWithFormat:@"共 %lu 个进程",
            (unsigned long)self.visibleProcesses.count];
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    if (self.visibleProcesses.count == 0) return nil;

    BOOL appsOnly = [self uidProbeUsable];
    if (appsOnly) {
        return @"只列出应用进程（UID 501）。点任意一行查看该进程的库地址，再点可 dump 模块。";
    }
    return @"UID 501 为移动用户（普通 App），其余多为系统守护进程。点任意一行查看该进程加载的模块与基址。";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kProcessCellIdentifier];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:kProcessCellIdentifier];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
        cell.detailTextLabel.font = [UIFont monospacedDigitSystemFontOfSize:12.0
                                                                     weight:UIFontWeightRegular];
    }

    NSDictionary<NSString *, id> *row = self.visibleProcesses[(NSUInteger)indexPath.row];
    uint32_t uid = [row[@"uid"] unsignedIntValue];
    NSString *uidText = (uid == UINT32_MAX) ? @"未知" : [NSString stringWithFormat:@"%u", uid];

    cell.textLabel.text = row[@"name"];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"PID %@ · UID %@",
                                 row[@"pid"], uidText];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    NSDictionary<NSString *, id> *row = self.visibleProcesses[(NSUInteger)indexPath.row];
    ProcessDetailViewController *detail =
        [[ProcessDetailViewController alloc] initWithProcessName:row[@"name"]
                                                             pid:[row[@"pid"] intValue]
                                                        procAddr:[row[@"proc"] unsignedLongLongValue]];
    [self.navigationController pushViewController:detail animated:YES];
}

#pragma mark - UISearchResultsUpdating

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController
{
    [self applyFilter];
}

@end
