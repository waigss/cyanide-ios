//
//  ProcessListViewController.m
//  Cyanide
//
//  「进程」页。数据来源是内核里 struct proc 的 p_list 双向链表（经 kread 读取），
//  不是 sysctl(KERN_PROC_ALL) —— 后者对非特权 app 一律返回 EPERM，即使打完沙盒
//  补丁也一样。
//
//  读取整张表要上千次 kread，所以放在后台队列跑，完成后回主线程刷新界面。
//  本页只读，不改任何内核状态。
//

#import "ProcessListViewController.h"

#import "../kexploit/kutils.h"
#import "../kexploit/kexploit_opa334.h"

static NSString * const kProcessCellIdentifier = @"CyanideProcessCell";
static const int kProcessCapacity = 1024;

@interface ProcessListViewController () <UISearchResultsUpdating>

@property (nonatomic, strong) UISearchController *searchController;
@property (nonatomic, copy) NSArray<NSDictionary<NSString *, id> *> *allProcesses;
@property (nonatomic, copy) NSArray<NSDictionary<NSString *, id> *> *visibleProcesses;
@property (nonatomic, assign) BOOL loading;

@end

@implementation ProcessListViewController

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

    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                      target:self
                                                      action:@selector(reloadProcesses)];

    [self reloadProcesses];
}

#pragma mark - 读取

- (void)reloadProcesses
{
    if (self.loading) return;
    self.loading = YES;

    if (self.allProcesses.count == 0) {
        [self showPlaceholder:@"正在读取内核进程表…"];
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

    int count = proc_list_all(buffer, kProcessCapacity);

    NSMutableArray<NSDictionary<NSString *, id> *> *rows =
        [NSMutableArray arrayWithCapacity:(NSUInteger)MAX(count, 0)];

    for (int i = 0; i < count; i++) {
        NSString *name = [NSString stringWithUTF8String:buffer[i].name];
        if (name.length == 0) name = @"（未命名）";
        [rows addObject:@{
            @"name": name,
            @"pid":  @(buffer[i].pid),
            @"uid":  @(buffer[i].uid),
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

- (void)applyFilter
{
    NSString *query = self.searchController.searchBar.text ?: @"";
    query = [query stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    NSMutableArray<NSDictionary<NSString *, id> *> *filtered = [NSMutableArray array];
    for (NSDictionary<NSString *, id> *row in self.allProcesses) {
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

    if (filtered.count == 0) {
        if (!kexploit_krw_ready()) {
            [self showPlaceholder:@"内核读写尚未就绪。\n请先回到「设置」完成初始化，再回到本页刷新。"];
        } else if (query.length > 0) {
            [self showPlaceholder:[NSString stringWithFormat:@"没有匹配「%@」的进程", query]];
        } else {
            [self showPlaceholder:@"没有读取到进程"];
        }
    } else {
        [self hidePlaceholder];
    }

    [self.tableView reloadData];
}

- (void)showPlaceholder:(NSString *)text
{
    UILabel *label = [[UILabel alloc] init];
    label.text = text;
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    label.textColor = [UIColor secondaryLabelColor];
    label.frame = CGRectInset(self.tableView.bounds, 32.0, 32.0);
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.tableView.backgroundView = label;
}

- (void)hidePlaceholder
{
    self.tableView.backgroundView = nil;
}

#pragma mark - UITableViewDataSource

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return (NSInteger)self.visibleProcesses.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if (self.visibleProcesses.count == 0) return nil;

    NSUInteger appCount = 0;
    for (NSDictionary<NSString *, id> *row in self.visibleProcesses) {
        if ([row[@"uid"] unsignedIntValue] == 501) appCount++;
    }
    return [NSString stringWithFormat:@"共 %lu 个进程 · 其中应用进程 %lu 个",
            (unsigned long)self.visibleProcesses.count, (unsigned long)appCount];
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    if (self.visibleProcesses.count == 0) return nil;
    return @"UID 501 为移动用户（普通 App），其余多为系统守护进程。列表实时读取，不会缓存。";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kProcessCellIdentifier];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:kProcessCellIdentifier];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
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

#pragma mark - UISearchResultsUpdating

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController
{
    [self applyFilter];
}

@end
