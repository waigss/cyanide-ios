//
//  SymbolListViewController.m
//  Cyanide
//
//  解析目标模块的 Mach-O 符号表（LC_SYMTAB），把 nlist_64 里的名字和地址翻出来。
//  全程走内核页表直读，不附加目标进程。
//
//  说明：release 包被 strip 过，符号表里通常只剩「导出符号」；
//  如果需要 ObjC 类名/方法名，那些在 __objc_* 段里，是另一套解析。
//

#import "SymbolListViewController.h"

#import "CyanideLog.h"
#import "KernelUserMemory.h"

#import "../kexploit/kexploit_opa334.h"

#import <string.h>
#import <stdlib.h>

static const uint32_t kMHMagic64      = 0xFEEDFACF;
static const uint32_t kMHMagic32      = 0xFEEDFACE;
static const uint32_t kLCSEGMENT64    = 0x19;
static const uint32_t kLCSymtab       = 0x2;
static const uint32_t kNStab          = 0xE0;

static const NSUInteger kMaxSymtabBytes = 32u * 1024u * 1024u;
static const NSUInteger kMaxStrtabBytes = 64u * 1024u * 1024u;
static const NSUInteger kMaxSymbols     = 200000;

typedef struct {
    uint64_t address;
    char name[256];
} symbol_entry;

static uint32_t rd_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

@interface SymbolListViewController () <UISearchResultsUpdating>

@property (nonatomic, copy) NSString *processName;
@property (nonatomic, assign) int pid;
@property (nonatomic, assign) uint64_t procAddr;
@property (nonatomic, assign) uint64_t moduleBase;
@property (nonatomic, copy) NSString *moduleName;

@property (nonatomic, strong) NSArray<NSDictionary *> *allSymbols;
@property (nonatomic, strong) NSArray<NSDictionary *> *visibleSymbols;
@property (nonatomic, strong) UISearchController *searchController;
@property (nonatomic, strong) UILabel *statusLabel;

@end

@implementation SymbolListViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr
                         moduleBase:(uint64_t)moduleBase
                         moduleName:(NSString *)moduleName
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _processName = [processName copy];
        _pid = pid;
        _procAddr = procAddr;
        _moduleBase = moduleBase;
        _moduleName = [moduleName copy];
        _allSymbols = @[];
        _visibleSymbols = @[];
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = self.moduleName.length > 0 ? self.moduleName : @"符号";

    UISearchController *search = [[UISearchController alloc] initWithSearchResultsController:nil];
    search.searchResultsUpdater = self;
    search.obscuresBackgroundDuringPresentation = NO;
    search.searchBar.placeholder = @"搜索符号名";
    self.navigationItem.searchController = search;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.searchController = search;
    self.definesPresentationContext = YES;

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    self.statusLabel.textColor = [UIColor secondaryLabelColor];
    self.statusLabel.text = @"正在解析符号表…";
    self.tableView.backgroundView = self.statusLabel;

    [self loadSymbols];
}

#pragma mark - 读取

// 分块读一段目标内存到 NSData；任何一块失败就返回 nil。
- (NSData *)readRemote:(uint64_t)address size:(NSUInteger)size limit:(NSUInteger)limit
{
    if (size == 0) return [NSData data];
    if (size > limit) size = limit;

    NSMutableData *data = [NSMutableData dataWithCapacity:size];
    const NSUInteger chunk = 0x10000;
    uint8_t *buffer = malloc(chunk);
    if (!buffer) return nil;

    NSUInteger done = 0;
    while (done < size) {
        NSUInteger want = MIN(chunk, size - done);
        if (!kum_read(address + done, buffer, want)) {
            free(buffer);
            return nil;
        }
        [data appendBytes:buffer length:want];
        done += want;
    }
    free(buffer);
    return data;
}

- (void)loadSymbols
{
    if (!kexploit_krw_ready()) {
        [self setStatus:@"内核未就绪，请先在「进程」页初始化。"];
        return;
    }

    if (!kum_prepare(self.procAddr)) {
        [self setStatus:@"页表上下文准备失败（pmap/tte 不可用）。"];
        return;
    }

    uint64_t base = self.moduleBase;
    if (base == 0) {
        uint64_t guessed = 0;
        if (kum_main_executable_base(&guessed)) {
            base = guessed;
            self.moduleBase = guessed;
            cyanide_log(@"[符号] 模块基址未指定，改用主程序基址 0x%llx", base);
        } else {
            [self setStatus:@"模块基址不可用。"];
            return;
        }
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray<NSDictionary *> *symbols = [self parseSymbolsAtBase:base];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (symbols.count == 0) {
                [self setStatus:@"没解析到符号。\n可能是纯 strip 的二进制，或基址不对。"];
                return;
            }
            self.allSymbols = symbols;
            self.visibleSymbols = symbols;
            self.tableView.backgroundView = nil;
            [self.tableView reloadData];
        });
    });
}

- (void)setStatus:(NSString *)text
{
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = text;
        self.tableView.backgroundView = self.statusLabel;
        [self.tableView reloadData];
    });
}

- (NSArray<NSDictionary *> *)parseSymbolsAtBase:(uint64_t)base
{
    // 1) 读 Mach-O 头
    NSData *headerData = [self readRemote:base size:0x20 limit:0x20];
    if (headerData.length < 0x20) {
        cyanide_log(@"[符号] 读 Mach-O 头失败 @0x%llx", base);
        return @[];
    }

    const uint8_t *h = headerData.bytes;
    uint32_t magic = rd_u32(h);
    if (magic != kMHMagic64 && magic != kMHMagic32) {
        cyanide_log(@"[符号] 0x%llx 不是 Mach-O（magic=0x%08x）", base, magic);
        return @[];
    }
    BOOL is64 = (magic == kMHMagic64);

    uint32_t ncmds = rd_u32(h + 16);
    uint32_t sizeofcmds = rd_u32(h + 20);
    NSUInteger headerSize = is64 ? 0x20 : 0x1C;

    if (ncmds == 0 || ncmds > 4096 || sizeofcmds == 0 || sizeofcmds > 0x100000) {
        cyanide_log(@"[符号] load commands 异常 ncmds=%u size=%u", ncmds, sizeofcmds);
        return @[];
    }

    NSData *cmdsData = [self readRemote:base + headerSize size:sizeofcmds limit:0x100000];
    if (cmdsData.length < sizeofcmds) {
        cyanide_log(@"[符号] 读 load commands 失败");
        return @[];
    }

    const uint8_t *cmds = cmdsData.bytes;
    NSUInteger offset = 0;

    uint64_t textVmaddr = 0;
    BOOL hasText = NO;

    uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
    BOOL hasSymtab = NO;

    for (uint32_t i = 0; i < ncmds && offset + 8 <= (NSUInteger)sizeofcmds; i++) {
        uint32_t cmd = rd_u32(cmds + offset);
        uint32_t cmdsize = rd_u32(cmds + offset + 4);
        if (cmdsize < 8 || offset + cmdsize > (NSUInteger)sizeofcmds) break;

        if (cmd == kLCSEGMENT64 && cmdsize >= 72) {
            const uint8_t *seg = cmds + offset;
            char segname[17] = {0};
            memcpy(segname, seg + 8, 16);

            uint64_t vmaddr = rd_u64(seg + 24);

            if (strcmp(segname, "__TEXT") == 0) {
                textVmaddr = vmaddr;
                hasText = YES;
            }
        } else if (cmd == kLCSymtab && cmdsize >= 24) {
            const uint8_t *sym = cmds + offset;
            symoff = rd_u32(sym + 8);
            nsyms = rd_u32(sym + 12);
            stroff = rd_u32(sym + 16);
            strsize = rd_u32(sym + 20);
            hasSymtab = YES;
        }

        offset += cmdsize;
    }

    if (!hasSymtab || nsyms == 0 || strsize == 0) {
        cyanide_log(@"[符号] 没有 LC_SYMTAB（可能被 strip）");
        return @[];
    }

    if (nsyms > kMaxSymbols) nsyms = (uint32_t)kMaxSymbols;

    uint64_t slide = hasText ? (base - textVmaddr) : 0;
    NSUInteger nlistSize = is64 ? 16 : 12;

    NSData *symData = [self readRemote:base + symoff
                                  size:(NSUInteger)nsyms * nlistSize
                                 limit:kMaxSymtabBytes];
    NSData *strData = [self readRemote:base + stroff size:strsize limit:kMaxStrtabBytes];

    if (symData.length == 0 || strData.length == 0) {
        cyanide_log(@"[符号] 符号表/字符串表读取失败");
        return @[];
    }

    const uint8_t *symBytes = symData.bytes;
    const uint8_t *strBytes = strData.bytes;
    NSUInteger symCount = symData.length / nlistSize;
    NSUInteger strLen = strData.length;

    NSMutableArray<NSDictionary *> *rows = [NSMutableArray arrayWithCapacity:symCount];

    for (NSUInteger i = 0; i < symCount; i++) {
        const uint8_t *entry = symBytes + i * nlistSize;

        uint32_t n_strx = rd_u32(entry);
        uint8_t n_type = entry[4];
        uint64_t n_value = is64 ? rd_u64(entry + 8) : rd_u32(entry + 8);

        if (n_strx == 0 || n_strx >= strLen) continue;
        if ((n_type & kNStab) != 0) continue;   // 调试符号
        if (n_value == 0) continue;

        const char *name = (const char *)(strBytes + n_strx);
        NSUInteger maxLen = strLen - n_strx;
        NSUInteger len = strnlen(name, maxLen);
        if (len == 0 || len >= 256) continue;

        char buffer[256] = {0};
        memcpy(buffer, name, len);

        uint64_t address = n_value + slide;

        [rows addObject:@{
            @"name": [NSString stringWithUTF8String:buffer] ?: @"?",
            @"address": @(address),
        }];
    }

    [rows sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        uint64_t x = [a[@"address"] unsignedLongLongValue];
        uint64_t y = [b[@"address"] unsignedLongLongValue];
        if (x < y) return NSOrderedAscending;
        if (x > y) return NSOrderedDescending;
        return NSOrderedSame;
    }];

    cyanide_log(@"[符号] %@ 基址0x%llx nsyms=%u 解析出 %lu 条（slide=0x%llx）",
                self.moduleName ?: @"模块", base, nsyms, (unsigned long)rows.count, slide);

    return rows;
}

#pragma mark - 搜索

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController
{
    NSString *query = [searchController.searchBar.text stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];

    if (query.length == 0) {
        self.visibleSymbols = self.allSymbols;
    } else {
        NSMutableArray<NSDictionary *> *hit = [NSMutableArray array];
        for (NSDictionary *row in self.allSymbols) {
            if ([row[@"name"] rangeOfString:query options:NSCaseInsensitiveSearch].location != NSNotFound) {
                [hit addObject:row];
            }
        }
        self.visibleSymbols = hit;
    }

    [self.tableView reloadData];
}

#pragma mark - 表格

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return (NSInteger)self.visibleSymbols.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if (self.visibleSymbols.count == 0) return nil;
    return [NSString stringWithFormat:@"%@ · %lu 条符号 · base 0x%llx",
            self.moduleName ?: @"模块",
            (unsigned long)self.visibleSymbols.count,
            (unsigned long long)self.moduleBase];
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    if (self.visibleSymbols.count == 0) return nil;
    return @"来自 Mach-O 的 LC_SYMTAB（导出符号）。点一行复制「名字 地址」。";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"symbol"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:@"symbol"];
        cell.textLabel.font = [UIFont systemFontOfSize:14.0 weight:UIFontWeightMedium];
        cell.detailTextLabel.font = [UIFont monospacedDigitSystemFontOfSize:11.0
                                                                     weight:UIFontWeightRegular];
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    }

    NSDictionary *row = self.visibleSymbols[(NSUInteger)indexPath.row];
    uint64_t address = [row[@"address"] unsignedLongLongValue];

    cell.textLabel.text = row[@"name"];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"0x%llx", (unsigned long long)address];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    NSDictionary *row = self.visibleSymbols[(NSUInteger)indexPath.row];
    uint64_t address = [row[@"address"] unsignedLongLongValue];
    NSString *copy = [NSString stringWithFormat:@"%@ 0x%llx", row[@"name"], (unsigned long long)address];

    [UIPasteboard generalPasteboard].string = copy;
    cyanide_log(@"[符号] 已复制 %@", copy);
}

@end
