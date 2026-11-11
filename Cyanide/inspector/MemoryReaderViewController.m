//
//  MemoryReaderViewController.m
//  Cyanide
//

#import "MemoryReaderViewController.h"

#import "CyanideLog.h"
#import "KernelUserMemory.h"

#import "../kexploit/krw.h"
#import "../kexploit/kexploit_opa334.h"

#import <string.h>

typedef NS_ENUM(NSInteger, MemoryValueType) {
    MemoryValueTypeU8 = 0,
    MemoryValueTypeI8,
    MemoryValueTypeU16,
    MemoryValueTypeI16,
    MemoryValueTypeU32,
    MemoryValueTypeI32,
    MemoryValueTypeU64,
    MemoryValueTypeI64,
    MemoryValueTypeFloat,
    MemoryValueTypeDouble,
    MemoryValueTypePointer,
    MemoryValueTypeHexBytes,
};

static NSString * const kTypeTitles[] = {
    @"U8", @"I8", @"U16", @"I16", @"U32", @"I32",
    @"U64", @"I64", @"Float", @"Double", @"指针", @"十六进制",
};

@interface MemoryReaderViewController () <UITextFieldDelegate>

@property (nonatomic, copy) NSString *processName;
@property (nonatomic, assign) int pid;
@property (nonatomic, assign) uint64_t procAddr;

@property (nonatomic, strong) UITextField *addressField;
@property (nonatomic, strong) UITextField *sizeField;
@property (nonatomic, strong) UISegmentedControl *typeControl;
@property (nonatomic, strong) UITextView *resultView;
@property (nonatomic, strong) UILabel *chainLabel;

@property (nonatomic, strong) NSMutableArray<NSString *> *chain;

@end

@implementation MemoryReaderViewController

- (instancetype)initWithProcessName:(NSString *)processName
                                pid:(int)pid
                           procAddr:(uint64_t)procAddr
{
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _processName = [processName copy];
        _pid = pid;
        _procAddr = procAddr;
        _chain = [NSMutableArray array];
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = self.processName.length > 0 ? self.processName : @"读内存";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    UIScrollView *scroll = [[UIScrollView alloc] initWithFrame:CGRectZero];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    [self.view addSubview:scroll];

    UILabel *addressTitle = [self labelWithText:@"地址（十六进制，可省略 0x）" bold:YES];

    self.addressField = [[UITextField alloc] initWithFrame:CGRectZero];
    self.addressField.translatesAutoresizingMaskIntoConstraints = NO;
    self.addressField.borderStyle = UITextBorderStyleRoundedRect;
    self.addressField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.addressField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.addressField.keyboardType = UIKeyboardTypeASCIICapable;
    self.addressField.font = [UIFont monospacedSystemFontOfSize:15.0 weight:UIFontWeightRegular];
    self.addressField.placeholder = @"例如 0x102a00000";
    self.addressField.delegate = self;
    self.addressField.text = @"0x";

    UILabel *typeTitle = [self labelWithText:@"数据类型" bold:YES];

    NSMutableArray<NSString *> *titles = [NSMutableArray array];
    for (NSUInteger i = 0; i < sizeof(kTypeTitles) / sizeof(kTypeTitles[0]); i++) {
        [titles addObject:kTypeTitles[i]];
    }
    self.typeControl = [[UISegmentedControl alloc] initWithItems:titles];
    self.typeControl.translatesAutoresizingMaskIntoConstraints = NO;
    self.typeControl.selectedSegmentIndex = MemoryValueTypePointer;

    UIButton *readButton = [self buttonWithTitle:@"读取值" action:@selector(readValueTapped)];
    UIButton *followButton = [self buttonWithTitle:@"跟随指针（读 8 字节当地址）" action:@selector(followPointerTapped)];

    self.chainLabel = [self labelWithText:@"" bold:NO];
    self.chainLabel.numberOfLines = 0;
    self.chainLabel.font = [UIFont monospacedSystemFontOfSize:12.0 weight:UIFontWeightRegular];
    self.chainLabel.textColor = [UIColor secondaryLabelColor];

    self.resultView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.resultView.translatesAutoresizingMaskIntoConstraints = NO;
    self.resultView.editable = NO;
    self.resultView.font = [UIFont monospacedSystemFontOfSize:12.0 weight:UIFontWeightRegular];
    self.resultView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.resultView.layer.cornerRadius = 8.0;
    self.resultView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    self.resultView.text = @"输入地址后点「读取值」。\n\n读取走内核页表直读，不附加目标进程。";

    UILabel *sizeTitle = [self labelWithText:@"要读取的字节数（十进制或 0x 十六进制，上限 64MB）" bold:YES];

    self.sizeField = [[UITextField alloc] initWithFrame:CGRectZero];
    self.sizeField.translatesAutoresizingMaskIntoConstraints = NO;
    self.sizeField.borderStyle = UITextBorderStyleRoundedRect;
    self.sizeField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.sizeField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.sizeField.keyboardType = UIKeyboardTypeASCIICapable;
    self.sizeField.font = [UIFont monospacedSystemFontOfSize:15.0 weight:UIFontWeightRegular];
    self.sizeField.placeholder = @"例如 0x1000 或 4096";

    UIButton *exportButton = [self buttonWithTitle:@"读取原始字节 → 保存文件"
                                           action:@selector(exportRawTapped)];

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        addressTitle, self.addressField,
        sizeTitle, self.sizeField, exportButton,
        typeTitle, self.typeControl,
        readButton, followButton, self.chainLabel, self.resultView
    ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 10.0;
    [scroll addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],

        [stack.topAnchor constraintEqualToAnchor:scroll.topAnchor constant:16.0],
        [stack.leadingAnchor constraintEqualToAnchor:scroll.leadingAnchor constant:16.0],
        [stack.trailingAnchor constraintEqualToAnchor:scroll.trailingAnchor constant:-16.0],
        [stack.bottomAnchor constraintEqualToAnchor:scroll.bottomAnchor constant:-16.0],
        [stack.widthAnchor constraintEqualToAnchor:scroll.widthAnchor constant:-32.0],

        [self.addressField.heightAnchor constraintEqualToConstant:36.0],
        [self.sizeField.heightAnchor constraintEqualToConstant:36.0],
        [self.resultView.heightAnchor constraintEqualToConstant:260.0],
    ]];

    [self prepareContext];
}

- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
    [self.addressField becomeFirstResponder];
}

#pragma mark - UI 小工具

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
    button.titleLabel.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightSemibold];
    button.backgroundColor = [UIColor tertiarySystemFillColor];
    button.layer.cornerRadius = 9.0;
    NSLayoutConstraint *height = [button.heightAnchor constraintEqualToConstant:44.0];
    height.active = YES;
    [button addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

#pragma mark - 上下文

- (void)prepareContext
{
    if (!kexploit_krw_ready()) {
        self.resultView.text = @"内核未就绪。\n请先回到「进程」页初始化内核。";
        return;
    }

    if (!kum_prepare(self.procAddr)) {
        self.resultView.text = @"页表上下文准备失败。\n目标进程可能已退出，或 pmap/tte 不可用。";
        cyanide_log(@"[读内存] kum_prepare 失败 proc=0x%llx", self.procAddr);
        return;
    }

    cyanide_log(@"[读内存] 就绪 目标=%@ 地址空间 0x%llx-0x%llx",
                self.processName, kum_map_min(), kum_map_max());
}

- (uint64_t)parseAddress:(NSString *)text
{
    NSString *trimmed = [text stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([trimmed hasPrefix:@"0x"] || [trimmed hasPrefix:@"0X"]) {
        trimmed = [trimmed substringFromIndex:2];
    }
    if (trimmed.length == 0) return 0;

    unsigned long long value = 0;
    NSScanner *scanner = [NSScanner scannerWithString:trimmed];
    if (![scanner scanHexLongLong:&value]) return 0;
    if (![scanner isAtEnd]) return 0;

    return (uint64_t)value;
}

#pragma mark - 读取

- (void)readValueTapped
{
    [self.addressField resignFirstResponder];

    uint64_t address = [self parseAddress:self.addressField.text];
    if (address == 0) {
        self.resultView.text = @"地址解析失败，请输入十六进制地址。";
        return;
    }

    if (!kexploit_krw_ready() || !kum_prepare(self.procAddr)) {
        self.resultView.text = @"内核或页表上下文不可用。";
        return;
    }

    MemoryValueType type = (MemoryValueType)self.typeControl.selectedSegmentIndex;
    [self readType:type atAddress:address];
}

- (void)readType:(MemoryValueType)type atAddress:(uint64_t)address
{
    uint8_t buffer[32] = {0};

    size_t want = 1;
    switch (type) {
        case MemoryValueTypeU8:
        case MemoryValueTypeI8: want = 1; break;
        case MemoryValueTypeU16:
        case MemoryValueTypeI16: want = 2; break;
        case MemoryValueTypeU32:
        case MemoryValueTypeI32:
        case MemoryValueTypeFloat: want = 4; break;
        case MemoryValueTypeU64:
        case MemoryValueTypeI64:
        case MemoryValueTypeDouble:
        case MemoryValueTypePointer: want = 8; break;
        case MemoryValueTypeHexBytes: want = 32; break;
    }

    if (!kum_read(address, buffer, want)) {
        self.resultView.text = [NSString stringWithFormat:
            @"读取失败：0x%llx 在目标进程里没有映射。\n\n地址空间：0x%llx - 0x%llx",
            (unsigned long long)address, kum_map_min(), kum_map_max()];
        cyanide_log(@"[读内存] 失败 0x%llx（未映射）", address);
        return;
    }

    NSMutableString *text = [NSMutableString string];
    [text appendFormat:@"地址：0x%llx\n", (unsigned long long)address];
    [text appendFormat:@"类型：%@\n", kTypeTitles[self.typeControl.selectedSegmentIndex]];
    [text appendString:@"\n原始字节："];
    for (size_t i = 0; i < want; i++) {
        [text appendFormat:@"%02x ", buffer[i]];
    }
    [text appendString:@"\n\n解析值："];

    switch (type) {
        case MemoryValueTypeU8:
            [text appendFormat:@"%u", buffer[0]];
            break;
        case MemoryValueTypeI8:
            [text appendFormat:@"%d", (int)(int8_t)buffer[0]];
            break;
        case MemoryValueTypeU16: {
            uint16_t v = 0; memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"%u", v];
            break;
        }
        case MemoryValueTypeI16: {
            int16_t v = 0; memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"%d", v];
            break;
        }
        case MemoryValueTypeU32: {
            uint32_t v = 0; memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"%u", v];
            break;
        }
        case MemoryValueTypeI32: {
            int32_t v = 0; memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"%d", v];
            break;
        }
        case MemoryValueTypeU64: {
            uint64_t v = 0; memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"%llu", (unsigned long long)v];
            break;
        }
        case MemoryValueTypeI64: {
            int64_t v = 0; memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"%lld", v];
            break;
        }
        case MemoryValueTypeFloat: {
            float v = 0; memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"%.9g", v];
            break;
        }
        case MemoryValueTypeDouble: {
            double v = 0; memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"%.17g", v];
            break;
        }
        case MemoryValueTypePointer:
        case MemoryValueTypeHexBytes: {
            uint64_t v = 0;
            memcpy(&v, buffer, sizeof(v));
            [text appendFormat:@"0x%llx", (unsigned long long)v];

            if (type == MemoryValueTypePointer) {
                [text appendFormat:@"\n\n指针目标：0x%llx", (unsigned long long)v];

                uint8_t probe[8] = {0};
                if (v != 0 && kum_read(v, probe, sizeof(probe))) {
                    uint64_t head = 0;
                    memcpy(&head, probe, sizeof(head));
                    [text appendFormat:@"（可读，目标前 8 字节 = 0x%llx）",
                     (unsigned long long)head];
                } else {
                    [text appendString:@"（不可读 / 未映射）"];
                }
            }
            break;
        }
    }

    self.resultView.text = text;
    cyanide_log(@"[读内存] 0x%llx type=%ld -> %@",
                (unsigned long long)address, (long)type,
                [text stringByReplacingOccurrencesOfString:@"\n" withString:@" | "]);
}

- (uint64_t)parseSize:(NSString *)text
{
    NSString *trimmed = [text stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length == 0) return 0;

    unsigned long long value = 0;
    NSScanner *scanner = nil;

    if ([trimmed hasPrefix:@"0x"] || [trimmed hasPrefix:@"0X"]) {
        scanner = [NSScanner scannerWithString:[trimmed substringFromIndex:2]];
        if (![scanner scanHexLongLong:&value]) return 0;
    } else {
        scanner = [NSScanner scannerWithString:trimmed];
        if (![scanner scanUnsignedLongLong:&value]) return 0;
    }
    if (![scanner isAtEnd]) return 0;
    return (uint64_t)value;
}

// 从指定地址读原始字节并保存成文件；遇到未映射就停在那，保留已读部分。
- (void)exportRawTapped
{
    [self.addressField resignFirstResponder];
    [self.sizeField resignFirstResponder];

    uint64_t address = [self parseAddress:self.addressField.text];
    uint64_t size = [self parseSize:self.sizeField.text];

    if (address == 0 || size == 0) {
        self.resultView.text = @"请填写有效的起始地址和字节数。";
        return;
    }

    const uint64_t kMaxBytes = 64ULL * 1024ULL * 1024ULL;
    if (size > kMaxBytes) {
        self.resultView.text = [NSString stringWithFormat:
            @"单次上限 64MB，你填的是 %.1f MB。", (double)size / (1024.0 * 1024.0)];
        return;
    }

    if (!kexploit_krw_ready() || !kum_prepare(self.procAddr)) {
        self.resultView.text = @"内核或页表上下文不可用。";
        return;
    }

    self.resultView.text = [NSString stringWithFormat:
        @"正在读取 0x%llx 起共 %llu 字节…", (unsigned long long)address, (unsigned long long)size];

    NSString *processName = self.processName ?: @"proc";
    int pid = self.pid;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableData *data = [NSMutableData dataWithCapacity:(NSUInteger)MIN(size, kMaxBytes)];
        uint64_t done = 0;
        const uint64_t kChunk = 0x10000;   // 64KB 一块
        uint8_t *buffer = malloc((size_t)kChunk);
        uint64_t failedAt = 0;

        if (buffer) {
            while (done < size) {
                uint64_t want = MIN(kChunk, size - done);
                if (kum_read(address + done, buffer, (size_t)want)) {
                    [data appendBytes:buffer length:(NSUInteger)want];
                    done += want;
                    continue;
                }

                // 整块失败时按 16KB 页细分，尽量保住可读的前缀
                const uint64_t kPage = 0x4000;
                uint64_t sub = 0;
                BOOL progressed = NO;
                while (sub < want) {
                    uint64_t pageWant = MIN(kPage, want - sub);
                    if (!kum_read(address + done + sub, buffer, (size_t)pageWant)) break;
                    [data appendBytes:buffer length:(NSUInteger)pageWant];
                    sub += pageWant;
                    progressed = YES;
                }
                done += sub;
                if (!progressed) { failedAt = address + done; break; }
            }
            free(buffer);
        }

        NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                                  NSUserDomainMask, YES).firstObject;
        NSString *dumpDir = [documents stringByAppendingPathComponent:@"dumps"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dumpDir
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:NULL];

        NSDateFormatter *stamp = [[NSDateFormatter alloc] init];
        stamp.dateFormat = @"yyyyMMdd-HHmmss";
        NSString *fileName = [NSString stringWithFormat:@"%@-0x%llx-0x%llx-%@.bin",
                              processName,
                              (unsigned long long)address,
                              (unsigned long long)done,
                              [stamp stringFromDate:[NSDate date]]];
        NSString *path = [dumpDir stringByAppendingPathComponent:fileName];

        NSError *error = nil;
        BOOL wrote = data.length > 0 && [data writeToFile:path options:NSDataWritingAtomic error:&error];

        cyanide_log(@"[导出] %@(PID %d) 0x%llx 起 %llu 字节 -> 写出 %lu 字节 结果=%d 失败点=0x%llx",
                    processName, pid, (unsigned long long)address, (unsigned long long)size,
                    (unsigned long)data.length, wrote ? 1 : 0, (unsigned long long)failedAt);

        dispatch_async(dispatch_get_main_queue(), ^{
            NSMutableString *text = [NSMutableString string];
            if (wrote) {
                [text appendFormat:@"已保存 %lu 字节（请求 %llu）\n\n%@",
                 (unsigned long)data.length, (unsigned long long)size, path];
                if (data.length < size) {
                    [text appendFormat:@"\n\n注意：读到 0x%llx 后遇到未映射区域，已提前结束。",
                     (unsigned long long)failedAt];
                }
            } else if (data.length == 0) {
                [text appendFormat:@"一个字节都没读到。\n0x%llx 在目标进程里没有映射。",
                 (unsigned long long)address];
            } else {
                [text appendFormat:@"写入文件失败：%@", error.localizedDescription ?: @"未知错误"];
            }
            self.resultView.text = text;
        });
    });
}

- (void)followPointerTapped
{
    [self.addressField resignFirstResponder];

    uint64_t address = [self parseAddress:self.addressField.text];
    if (address == 0) {
        self.resultView.text = @"地址解析失败，请输入十六进制地址。";
        return;
    }

    if (!kexploit_krw_ready() || !kum_prepare(self.procAddr)) {
        self.resultView.text = @"内核或页表上下文不可用。";
        return;
    }

    uint8_t buffer[8] = {0};
    if (!kum_read(address, buffer, sizeof(buffer))) {
        self.resultView.text = [NSString stringWithFormat:
            @"0x%llx 未映射，无法跟随。", (unsigned long long)address];
        return;
    }

    uint64_t target = 0;
    memcpy(&target, buffer, sizeof(target));

    [self.chain addObject:[NSString stringWithFormat:@"0x%llx", (unsigned long long)address]];
    self.chainLabel.text = [[self.chain componentsJoinedByString:@" → "]
                            stringByAppendingFormat:@" → 0x%llx", (unsigned long long)target];

    if (target == 0) {
        self.resultView.text = [NSString stringWithFormat:
            @"0x%llx 处是空指针（0x0）。", (unsigned long long)address];
        return;
    }

    uint8_t probe[8] = {0};
    BOOL readable = kum_read(target, probe, sizeof(probe));

    self.addressField.text = [NSString stringWithFormat:@"0x%llx", (unsigned long long)target];

    [self readType:MemoryValueTypePointer atAddress:target];

    if (!readable) {
        self.resultView.text = [self.resultView.text stringByAppendingFormat:
            @"\n\n提示：目标 0x%llx 当前不可读（可能未映射或是无效指针）。",
            (unsigned long long)target];
    }
}

@end
