//
//  ProbeListViewController.m
//  Cyanide
//
//  探针表行格式（每行一条，空白分隔）：
//      probe_01.bin    base + 0x16920000    8
//  也就是「文件名 / 偏移表达式 / 字节数」。偏移可以写 base + 0x…，也可以只写 0x…；
//  字节数支持十进制或 0x 十六进制。
//

#import "ProbeListViewController.h"

#import "CyanideLog.h"
#import "KernelUserMemory.h"

#import "../kexploit/kexploit_opa334.h"

#import <string.h>

static NSString * const kProbeFileName = @"probes.txt";

@interface ProbeListViewController ()

@property (nonatomic, copy) NSString *processName;
@property (nonatomic, assign) int pid;
@property (nonatomic, assign) uint64_t procAddr;

@property (nonatomic, assign) uint64_t base;
@property (nonatomic, assign) BOOL baseReady;
@property (nonatomic, strong) NSMutableArray<NSMutableDictionary *> *probes;
@property (nonatomic, assign) BOOL running;

@end

@implementation ProbeListViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _processName = [processName copy];
        _pid = pid;
        _procAddr = procAddr;
        _probes = [NSMutableArray array];
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = @"探针表";
    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithTitle:@"全部读取"
                                         style:UIBarButtonItemStyleDone
                                        target:self
                                        action:@selector(readAllTapped)],
        [[UIBarButtonItem alloc] initWithTitle:@"重新载入"
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(reloadTapped)],
    ];

    [self prepareContext];
    [self loadProbeFile];
    [self reloadProbes];
}

#pragma mark - 探针文件

- (NSString *)probeDirPath
{
    NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                              NSUserDomainMask, YES).firstObject;
    NSString *dir = [documents stringByAppendingPathComponent:@"dumps"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                             withIntermediateDirectories:YES
                                              attributes:nil
                                                   error:NULL];
    return dir;
}

- (NSString *)probeFilePath
{
    return [[self probeDirPath] stringByAppendingPathComponent:kProbeFileName];
}

- (NSString *)defaultProbeTemplate
{
    return @"# 每行：文件名 偏移 字节数    （偏移可写 base + 0x…，也可以只写 0x…）\n"
           "probe_01.bin    base + 0x16920000    8\n"
           "probe_02.bin    base + 0x16957000    8\n"
           "probe_03.bin    base + 0x1691F000    8\n"
           "probe_04.bin    base + 0x16956000    8\n"
           "probe_05.bin    base + 0x16A63000    8\n"
           "probe_06.bin    base + 0x16972000    8\n"
           "probe_07.bin    base + 0x16A62000    8\n"
           "probe_08.bin    base + 0x167C8B20    8\n"
           "probe_09.bin    base + 0x16955000    8\n"
           "probe_10.bin    base + 0x16957030    8\n"
           "probe_11.bin    base + 0x15DACBF8    8\n"
           "probe_12.bin    base + 0x16944000    8\n"
           "probe_13.bin    base + 0x1555A880    8\n"
           "probe_14.bin    base + 0x16A1F020    8\n"
           "probe_15.bin    base + 0x16971000    8\n"
           "probe_16.bin    base + 0x15D1D370    8\n"
           "probe_17.bin    base + 0x167C7B20    8\n"
           "probe_18.bin    base + 0x15DABBF8    8\n"
           "probe_19.bin    base + 0x167BC000    8\n"
           "probe_20.bin    base + 0x15DACE18    8\n";
}

- (void)loadProbeFile
{
    NSString *path = [self probeFilePath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [[self defaultProbeTemplate] writeToFile:path atomically:YES
                                        encoding:NSUTF8StringEncoding error:NULL];
        cyanide_log(@"[探针] 已生成默认探针表：%@", path);
    }
}

- (void)reloadProbes
{
    [self.probes removeAllObjects];

    NSString *path = [self probeFilePath];
    NSString *content = [NSString stringWithContentsOfFile:path
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    if (content.length == 0) {
        cyanide_log(@"[探针] 探针表为空或读取失败：%@", path);
        [self.tableView reloadData];
        return;
    }

    NSArray<NSString *> *lines = [content componentsSeparatedByCharactersInSet:
                                  [NSCharacterSet newlineCharacterSet]];

    for (NSString *rawLine in lines) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (line.length == 0) continue;
        if ([line hasPrefix:@"#"]) continue;

        NSMutableArray<NSString *> *tokens = [NSMutableArray array];
        for (NSString *tok in [line componentsSeparatedByCharactersInSet:
                               [NSCharacterSet whitespaceAndNewlineCharacterSet]]) {
            if (tok.length > 0) [tokens addObject:tok];
        }
        if (tokens.count < 3) continue;

        NSString *name = tokens.firstObject;
        NSInteger size = (NSInteger)[self parseNumber:tokens.lastObject];

        NSMutableArray<NSString *> *offsetToks = [NSMutableArray array];
        for (NSUInteger i = 1; i + 1 < tokens.count; i++) {
            [offsetToks addObject:tokens[i]];
        }
        NSString *offsetExpr = [[offsetToks componentsJoinedByString:@""]
                                stringByReplacingOccurrencesOfString:@"base" withString:@""];
        offsetExpr = [offsetExpr stringByReplacingOccurrencesOfString:@"+" withString:@""];
        uint64_t offset = [self parseNumber:offsetExpr];

        NSMutableDictionary *probe = [@{
            @"name": name,
            @"offset": @(offset),
            @"size": @(size),
            @"status": @"待读取",
        } mutableCopy];
        [self.probes addObject:probe];
    }

    cyanide_log(@"[探针] 载入 %lu 条探针（文件：%@）", (unsigned long)self.probes.count, path);
    [self.tableView reloadData];
}

// 支持 0x 十六进制与十进制
- (uint64_t)parseNumber:(NSString *)text
{
    NSString *s = [[text stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if (s.length == 0) return 0;

    unsigned long long value = 0;
    NSScanner *scanner = nil;
    if ([s hasPrefix:@"0x"]) {
        scanner = [NSScanner scannerWithString:[s substringFromIndex:2]];
        if (![scanner scanHexLongLong:&value]) return 0;
    } else {
        scanner = [NSScanner scannerWithString:s];
        if (![scanner scanUnsignedLongLong:&value]) return 0;
    }
    return (uint64_t)value;
}

#pragma mark - 基址

- (void)prepareContext
{
    if (!kexploit_krw_ready()) {
        cyanide_log(@"[探针] 内核未就绪");
        return;
    }

    if (!kum_prepare(self.procAddr)) {
        cyanide_log(@"[探针] 页表上下文准备失败 proc=0x%llx", self.procAddr);
        return;
    }

    uint64_t base = 0;
    if (kum_main_executable_base(&base)) {
        self.base = base;
        self.baseReady = YES;
        cyanide_log(@"[探针] 主程序基址 = 0x%llx（%@ PID %d）", base, self.processName, self.pid);
    } else {
        cyanide_log(@"[探针] 没能定位主程序基址，探针无法换算绝对地址");
    }
}

#pragma mark - 批量读取

- (void)reloadTapped
{
    [self loadProbeFile];
    [self reloadProbes];
}

- (void)readAllTapped
{
    if (self.running) return;
    if (!self.baseReady) {
        [self presentAlert:@"主程序基址不可用" message:@"没能定位主程序基址，无法换算探针地址。"];
        return;
    }
    if (self.probes.count == 0) {
        [self presentAlert:@"探针表是空的" message:@"请编辑 Documents/dumps/probes.txt 后再试。"];
        return;
    }

    self.running = YES;
    NSString *dir = [self probeDirPath];
    uint64_t base = self.base;

    for (NSMutableDictionary *probe in self.probes) {
        probe[@"status"] = @"排队";
    }
    [self.tableView reloadData];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSUInteger okCount = 0;

        for (NSUInteger i = 0; i < self.probes.count; i++) {
            NSMutableDictionary *probe = self.probes[i];
            NSString *name = probe[@"name"];
            uint64_t offset = [probe[@"offset"] unsignedLongLongValue];
            NSUInteger size = (NSUInteger)[probe[@"size"] unsignedIntegerValue];
            uint64_t address = base + offset;

            if (size == 0 || size > 0x1000000) {
                probe[@"status"] = @"大小无效";
                continue;
            }

            NSMutableData *data = [NSMutableData dataWithLength:size];
            BOOL ok = kum_read(address, data.mutableBytes, size);

            if (ok) {
                NSString *path = [dir stringByAppendingPathComponent:name];
                NSError *error = nil;
                ok = [data writeToFile:path options:NSDataWritingAtomic error:&error];
                probe[@"status"] = ok ? @"完成" : @"写文件失败";
                if (ok) okCount += 1;
                cyanide_log(@"[探针] %@ 0x%llx(+0x%llx) %lu 字节 -> %@",
                            name, address, offset, (unsigned long)size, ok ? @"OK" : @"写入失败");
            } else {
                probe[@"status"] = @"地址未映射";
                cyanide_log(@"[探针] %@ 0x%llx(+0x%llx) 读取失败（未映射）",
                            name, address, offset);
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                [self.tableView reloadData];
            });
        }

        cyanide_log(@"[探针] 全部结束：成功 %lu / 共 %lu 条，目录 %@",
                    (unsigned long)okCount, (unsigned long)self.probes.count, dir);

        dispatch_async(dispatch_get_main_queue(), ^{
            self.running = NO;
            [self.tableView reloadData];
            [self presentAlert:@"探针读取完成"
                       message:[NSString stringWithFormat:@"成功 %lu / 共 %lu 条\n\n文件目录：\n%@",
                                (unsigned long)okCount, (unsigned long)self.probes.count, dir]];
        });
    });
}

#pragma mark - 表格

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return section == 0 ? 1 : (NSInteger)self.probes.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if (section == 0) return @"主程序基址";
    return [NSString stringWithFormat:@"探针（%lu 条）", (unsigned long)self.probes.count];
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    if (section != 1) return nil;
    return [NSString stringWithFormat:
            @"表文件：dumps/%@\n每行格式：文件名 偏移 字节数（偏移可写 base + 0x…）。改完点「重新载入」。",
            kProbeFileName];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"probe"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:@"probe"];
        cell.detailTextLabel.font = [UIFont monospacedDigitSystemFontOfSize:11.0
                                                                     weight:UIFontWeightRegular];
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    }

    if (indexPath.section == 0) {
        cell.textLabel.text = self.baseReady
            ? [NSString stringWithFormat:@"0x%llx", (unsigned long long)self.base]
            : @"未定位";
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ · PID %d", self.processName, self.pid];
        cell.accessoryType = UITableViewCellAccessoryNone;
        return cell;
    }

    NSDictionary *probe = self.probes[(NSUInteger)indexPath.row];
    uint64_t offset = [probe[@"offset"] unsignedLongLongValue];
    uint64_t address = self.base + offset;

    cell.textLabel.text = probe[@"name"];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"0x%llx (+0x%llx) · %@ 字节 · %@",
                                 (unsigned long long)address, (unsigned long long)offset,
                                 probe[@"size"], probe[@"status"]];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section != 1) return;

    NSDictionary *probe = self.probes[(NSUInteger)indexPath.row];
    NSString *path = [[self probeDirPath] stringByAppendingPathComponent:probe[@"name"]];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [self presentAlert:@"文件已存在" message:path];
    } else {
        [self presentAlert:@"文件还没生成" message:@"点右上角「全部读取」先跑一次。"];
    }
}

- (void)presentAlert:(NSString *)title message:(NSString *)message
{
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:title
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
