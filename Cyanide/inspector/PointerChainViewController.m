//
//  PointerChainViewController.m
//  Cyanide
//
//  链脚本格式（每行一步，空白分隔）：偏移 类型
//      # 类型：ptr u64 int64 u32 int32 u16 int16 u8 int8 float double
//      0x16A627B0 ptr      ← 主程序基址 + 偏移，读 8 字节当指针
//      0xF8 ptr            ← 上一级指针 + 0xF8，再读 8 字节当指针
//      0x98 ptr
//      0xA8 int32          ← 最后一级读整数
//
//  执行语义：addr 从主程序基址开始；每一步 addr += 偏移，按类型读值；
//  类型是 ptr 时，读到的值成为下一级的 addr；最后一步的值就是结果。
//

#import "PointerChainViewController.h"

#import "CyanideLog.h"
#import "KernelUserMemory.h"

#import "../kexploit/kexploit_opa334.h"

#import <string.h>
#import <stdlib.h>

static NSString * const kChainFileName = @"chain.txt";

@interface PointerChainViewController () <UITextViewDelegate>

@property (nonatomic, copy) NSString *processName;
@property (nonatomic, assign) int pid;
@property (nonatomic, assign) uint64_t procAddr;

@property (nonatomic, assign) uint64_t base;
@property (nonatomic, assign) BOOL baseReady;
@property (nonatomic, assign) BOOL running;

@property (nonatomic, strong) UITextView *scriptView;
@property (nonatomic, strong) UITextView *resultView;
@property (nonatomic, strong) UILabel *headerLabel;

@end

@implementation PointerChainViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr
{
    self = [super initWithNibName:nil bundle:nil];
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

    self.title = @"指针链";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"执行"
                                         style:UIBarButtonItemStyleDone
                                        target:self
                                        action:@selector(runTapped)];

    self.headerLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.headerLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.headerLabel.numberOfLines = 0;
    self.headerLabel.font = [UIFont monospacedSystemFontOfSize:12.0 weight:UIFontWeightRegular];

    UILabel *scriptTitle = [self labelWithText:@"链脚本（每行：偏移 类型）" bold:YES];

    self.scriptView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.scriptView.translatesAutoresizingMaskIntoConstraints = NO;
    self.scriptView.font = [UIFont monospacedSystemFontOfSize:12.0 weight:UIFontWeightRegular];
    self.scriptView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.scriptView.layer.cornerRadius = 8.0;
    self.scriptView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    self.scriptView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.scriptView.autocorrectionType = UITextAutocorrectionTypeNo;

    UIButton *saveButton = [self buttonWithTitle:@"保存脚本" action:@selector(saveTapped)];
    UIButton *reloadButton = [self buttonWithTitle:@"重新载入脚本" action:@selector(loadScript)];

    UILabel *resultTitle = [self labelWithText:@"逐级结果" bold:YES];

    self.resultView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.resultView.translatesAutoresizingMaskIntoConstraints = NO;
    self.resultView.editable = NO;
    self.resultView.font = [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular];
    self.resultView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.resultView.layer.cornerRadius = 8.0;
    self.resultView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    self.resultView.text = @"点右上角「执行」开始逐级解析。";

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        self.headerLabel, scriptTitle, self.scriptView, saveButton, reloadButton,
        resultTitle, self.resultView
    ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 8.0;
    [self.view addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:12.0],
        [stack.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16.0],
        [stack.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16.0],
        [stack.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-12.0],
        [self.scriptView.heightAnchor constraintEqualToConstant:170.0],
        [self.resultView.heightAnchor constraintGreaterThanOrEqualToConstant:220.0],
    ]];

    [self prepareContext];
    [self loadScript];
}

#pragma mark - UI 工具

- (UILabel *)labelWithText:(NSString *)text bold:(BOOL)bold
{
    UILabel *label = [[UILabel alloc] initWithFrame:CGRectZero];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.text = text;
    label.numberOfLines = 0;
    label.font = bold ? [UIFont systemFontOfSize:13.0 weight:UIFontWeightSemibold]
                      : [UIFont systemFontOfSize:12.0 weight:UIFontWeightRegular];
    label.textColor = bold ? [UIColor labelColor] : [UIColor secondaryLabelColor];
    return label;
}

- (UIButton *)buttonWithTitle:(NSString *)title action:(SEL)action
{
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button setTitle:title forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont systemFontOfSize:15.0 weight:UIFontWeightSemibold];
    button.backgroundColor = [UIColor tertiarySystemFillColor];
    button.layer.cornerRadius = 9.0;
    NSLayoutConstraint *height = [button.heightAnchor constraintEqualToConstant:40.0];
    height.active = YES;
    [button addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

#pragma mark - 上下文与脚本

- (NSString *)dumpDir
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

- (NSString *)scriptPath
{
    return [[self dumpDir] stringByAppendingPathComponent:kChainFileName];
}

- (NSString *)defaultScript
{
    return @"# 每行一步：偏移 类型\n"
           @"# 类型：ptr u64 int64 u32 int32 u16 int16 u8 int8 float double\n"
           @"# 语义：addr 从主程序基址开始；每步 addr+=偏移，按类型读值；\n"
           @"#       ptr 表示把读到的值当作下一级的地址。\n"
           @"0x16A627B0 ptr\n"
           @"0xF8 ptr\n"
           @"0x98 ptr\n"
           @"0xA8 int32\n";
}

- (void)prepareContext
{
    if (!kexploit_krw_ready()) {
        self.headerLabel.text = @"内核未就绪";
        cyanide_log(@"[指针链] 内核未就绪");
        return;
    }

    if (!kum_prepare(self.procAddr)) {
        self.headerLabel.text = [NSString stringWithFormat:@"%@ · PID %d\n页表上下文准备失败", self.processName, self.pid];
        cyanide_log(@"[指针链] kum_prepare 失败 proc=0x%llx", self.procAddr);
        return;
    }

    uint64_t base = 0;
    if (kum_main_executable_base(&base)) {
        self.base = base;
        self.baseReady = YES;
    }

    self.headerLabel.text = [NSString stringWithFormat:
        @"进程 %@ · PID %d\n主程序基址 %@",
        self.processName, self.pid,
        self.baseReady ? [NSString stringWithFormat:@"0x%llx", (unsigned long long)self.base] : @"（未定位）"];

    cyanide_log(@"[指针链] 就绪 %@ PID %d 基址=%@", self.processName, self.pid,
                self.baseReady ? [NSString stringWithFormat:@"0x%llx", (unsigned long long)self.base] : @"未定位");
}

- (void)loadScript
{
    NSString *path = [self scriptPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [[self defaultScript] writeToFile:path atomically:YES
                                 encoding:NSUTF8StringEncoding error:NULL];
        cyanide_log(@"[指针链] 已生成默认链脚本：%@", path);
    }

    NSString *content = [NSString stringWithContentsOfFile:path
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    self.scriptView.text = content.length > 0 ? content : [self defaultScript];
}

- (void)saveTapped
{
    NSString *path = [self scriptPath];
    NSError *error = nil;
    BOOL ok = [self.scriptView.text writeToFile:path atomically:YES
                                       encoding:NSUTF8StringEncoding error:&error];
    cyanide_log(@"[指针链] 保存脚本 %@ -> %d %@", path, ok ? 1 : 0, error.localizedDescription ?: @"");
    [self showAlert:ok ? @"已保存" : @"保存失败"
            message:ok ? path : (error.localizedDescription ?: @"未知错误")];
}

#pragma mark - 解析与执行

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

- (void)runTapped
{
    if (self.running) return;
    if (!kexploit_krw_ready() || !kum_prepare(self.procAddr)) {
        [self showAlert:@"不可用" message:@"内核或页表上下文不可用。"];
        return;
    }
    if (!self.baseReady) {
        uint64_t base = 0;
        if (kum_main_executable_base(&base)) {
            self.base = base;
            self.baseReady = YES;
        } else {
            [self showAlert:@"主程序基址不可用" message:@"没能定位主程序基址，无法换算探针地址。"];
            return;
        }
    }

    NSArray<NSString *> *lines = [self.scriptView.text componentsSeparatedByCharactersInSet:
                                  [NSCharacterSet newlineCharacterSet]];

    NSMutableArray<NSDictionary *> *steps = [NSMutableArray array];
    for (NSString *rawLine in lines) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;

        NSMutableArray<NSString *> *tokens = [NSMutableArray array];
        for (NSString *tok in [line componentsSeparatedByCharactersInSet:
                               [NSCharacterSet whitespaceAndNewlineCharacterSet]]) {
            if (tok.length > 0) [tokens addObject:tok];
        }
        if (tokens.count < 2) continue;

        [steps addObject:@{
            @"offset": @([self parseNumber:tokens[0]]),
            @"type": [tokens[1] lowercaseString],
        }];
    }

    if (steps.count == 0) {
        [self showAlert:@"脚本是空的" message:@"至少写一行「偏移 类型」。"];
        return;
    }

    self.running = YES;
    self.resultView.text = @"执行中…";

    uint64_t base = self.base;
    NSString *processName = self.processName;
    int pid = self.pid;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableString *out = [NSMutableString string];
        [out appendFormat:@"%@ (PID %d)  基址 0x%llx\n\n",
         processName, pid, (unsigned long long)base];

        uint64_t addr = base;
        BOOL failed = NO;
        NSString *failedNote = nil;

        for (NSUInteger i = 0; i < steps.count; i++) {
            uint64_t offset = [steps[i][@"offset"] unsignedLongLongValue];
            NSString *type = steps[i][@"type"];
            addr += offset;

            uint8_t buf[8] = {0};
            size_t want = 8;
            NSString *desc = nil;

            if ([type isEqualToString:@"float"]) {
                want = 4;
                if (!kum_read(addr, buf, want)) { failed = YES; failedNote = @"未映射"; break; }
                float v = 0; memcpy(&v, buf, sizeof(v));
                desc = [NSString stringWithFormat:@"%.9g (float)", v];
            } else if ([type isEqualToString:@"double"]) {
                want = 8;
                if (!kum_read(addr, buf, want)) { failed = YES; failedNote = @"未映射"; break; }
                double v = 0; memcpy(&v, buf, sizeof(v));
                desc = [NSString stringWithFormat:@"%.17g (double)", v];
            } else if ([type isEqualToString:@"u8"] || [type isEqualToString:@"int8"]) {
                want = 1;
                if (!kum_read(addr, buf, want)) { failed = YES; failedNote = @"未映射"; break; }
                desc = [type isEqualToString:@"u8"]
                    ? [NSString stringWithFormat:@"%u (u8)", buf[0]]
                    : [NSString stringWithFormat:@"%d (int8)", (int)(int8_t)buf[0]];
            } else if ([type isEqualToString:@"u16"] || [type isEqualToString:@"int16"]) {
                want = 2;
                if (!kum_read(addr, buf, want)) { failed = YES; failedNote = @"未映射"; break; }
                if ([type isEqualToString:@"u16"]) {
                    uint16_t v = 0; memcpy(&v, buf, sizeof(v));
                    desc = [NSString stringWithFormat:@"%u (u16)", v];
                } else {
                    int16_t v = 0; memcpy(&v, buf, sizeof(v));
                    desc = [NSString stringWithFormat:@"%d (int16)", v];
                }
            } else if ([type isEqualToString:@"u32"] || [type isEqualToString:@"int32"]) {
                want = 4;
                if (!kum_read(addr, buf, want)) { failed = YES; failedNote = @"未映射"; break; }
                if ([type isEqualToString:@"u32"]) {
                    uint32_t v = 0; memcpy(&v, buf, sizeof(v));
                    desc = [NSString stringWithFormat:@"%u (u32)", v];
                } else {
                    int32_t v = 0; memcpy(&v, buf, sizeof(v));
                    desc = [NSString stringWithFormat:@"%d (int32)", v];
                }
            } else {
                // ptr / u64 / int64 都读 8 字节
                want = 8;
                if (!kum_read(addr, buf, want)) { failed = YES; failedNote = @"未映射"; break; }
                uint64_t v = 0; memcpy(&v, buf, sizeof(v));

                if ([type isEqualToString:@"int64"]) {
                    desc = [NSString stringWithFormat:@"%lld (int64)", (long long)v];
                } else if ([type isEqualToString:@"u64"]) {
                    desc = [NSString stringWithFormat:@"%llu (u64)", (unsigned long long)v];
                } else {
                    desc = [NSString stringWithFormat:@"0x%llx (ptr)", (unsigned long long)v];
                }

                if ([type isEqualToString:@"ptr"]) {
                    [out appendFormat:@"[%lu] +0x%llx → 0x%llx\n     读取 %@\n",
                     (unsigned long)i + 1, (unsigned long long)offset,
                     (unsigned long long)addr, desc];
                    addr = v;   // 指针值成为下一级地址
                    continue;
                }
            }

            [out appendFormat:@"[%lu] +0x%llx → 0x%llx\n     读取 %@\n",
             (unsigned long)i + 1, (unsigned long long)offset,
             (unsigned long long)addr, desc];
        }

        if (!failed) {
            [out appendFormat:@"\n最终地址 0x%llx\n", (unsigned long long)addr];
            cyanide_log(@"[指针链] %@ 完成，最终地址=0x%llx", processName, addr);
        } else {
            [out appendFormat:@"\n断在第 %lu 步：0x%llx %@\n",
             (unsigned long)steps.count, (unsigned long long)addr, failedNote ?: @""];
            cyanide_log(@"[指针链] %@ 断在 0x%llx（%@）", processName, addr, failedNote ?: @"");
        }

        cyanide_log(@"[指针链] 明细：%@", [out stringByReplacingOccurrencesOfString:@"\n" withString:@" | "]);

        dispatch_async(dispatch_get_main_queue(), ^{
            self.running = NO;
            self.resultView.text = out;
        });
    });
}

- (void)showAlert:(NSString *)title message:(NSString *)message
{
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:title
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
