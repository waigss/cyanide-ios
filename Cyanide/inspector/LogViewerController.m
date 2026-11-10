//
//  LogViewerController.m
//  Cyanide
//

#import "LogViewerController.h"
#import "CyanideLog.h"

@interface LogViewerController ()

@property (nonatomic, strong) UITextView *textView;
@property (nonatomic, strong) NSTimer *refreshTimer;
@property (nonatomic, assign) NSUInteger lastLineCount;

@end

@implementation LogViewerController

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = @"日志";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    self.textView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.textView.translatesAutoresizingMaskIntoConstraints = NO;
    self.textView.editable = NO;
    self.textView.selectable = YES;
    self.textView.alwaysBounceVertical = YES;
    self.textView.font = [UIFont monospacedSystemFontOfSize:10.0 weight:UIFontWeightRegular];
    self.textView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    [self.view addSubview:self.textView];

    [NSLayoutConstraint activateConstraints:@[
        [self.textView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.textView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [self.textView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.textView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    ]];

    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAction
                                                      target:self
                                                      action:@selector(shareLog)],
        [[UIBarButtonItem alloc] initWithTitle:@"清空"
                                         style:UIBarButtonItemStylePlain
                                        target:self
                                        action:@selector(clearLog)],
    ];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];

    [self reloadText];
    if (!self.refreshTimer) {
        self.refreshTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                           target:self
                                                         selector:@selector(tickReload)
                                                         userInfo:nil
                                                          repeats:YES];
    }
}

- (void)viewWillDisappear:(BOOL)animated
{
    [super viewWillDisappear:animated];
    [self.refreshTimer invalidate];
    self.refreshTimer = nil;
}

- (void)tickReload
{
    if (!self.view.window) return;

    NSUInteger count = clog_lines().count;
    if (count != self.lastLineCount) {
        [self reloadText];
    }
}

- (void)reloadText
{
    NSArray<NSString *> *lines = clog_lines();
    self.lastLineCount = lines.count;

    NSMutableString *text = [NSMutableString string];
    [text appendFormat:@"日志文件：%@\n", clog_file_path()];
    [text appendFormat:@"共 %lu 行（在「文件」App → 我的 iPhone → Cyanide 里可以导出 cyanide.log）\n\n",
     (unsigned long)lines.count];

    if (lines.count == 0) {
        [text appendString:@"（还没有日志）\n"];
    } else {
        for (NSString *line in lines) {
            [text appendFormat:@"%@\n", line];
        }
    }

    self.textView.text = text;

    if (lines.count > 0) {
        NSRange end = NSMakeRange(text.length - 1, 1);
        [self.textView scrollRangeToVisible:end];
    }
}

- (void)clearLog
{
    clog_clear();
    [self reloadText];
}

- (void)shareLog
{
    NSString *path = clog_file_path();
    NSURL *url = [NSURL fileURLWithPath:path];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [self reloadText];
        url = nil;
    }

    UIActivityViewController *share = url
        ? [[UIActivityViewController alloc] initWithActivityItems:@[url] applicationActivities:nil]
        : [[UIActivityViewController alloc] initWithActivityItems:@[clog_lines()] applicationActivities:nil];
    share.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItems.firstObject;

    [self presentViewController:share animated:YES completion:nil];
}

@end
