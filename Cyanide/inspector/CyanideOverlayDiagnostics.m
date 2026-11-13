//
//  CyanideOverlayDiagnostics.m
//  Cyanide
//

#import "CyanideOverlayDiagnostics.h"

#import "../TaskRop/RemoteCall.h"
#import "../tweaks/remote_objc.h"
#import "../kexploit/kexploit_opa334.h"
#import "../SettingsViewController.h"
#import "CyanideLog.h"

#include <string.h>

// 把远程对象的 -description 读回来（SpringBoard 里的 frame/hidden 都在里面）
static NSString *dx_description(uint64_t object)
{
    if (!r_is_objc_ptr(object)) return nil;

    uint64_t selDescription = r_sel("description");
    if (!selDescription) return nil;
    uint64_t string = r_msg(object, selDescription, 0, 0, 0, 0);
    if (!r_is_objc_ptr(string)) return nil;

    uint64_t selUTF8 = r_sel("UTF8String");
    if (!selUTF8) return nil;
    uint64_t cstring = r_msg(string, selUTF8, 0, 0, 0, 0);
    if (!r_is_objc_ptr(cstring)) return nil;

    char buffer[512];
    memset(buffer, 0, sizeof(buffer));
    if (!remote_read(cstring, buffer, sizeof(buffer) - 1)) return nil;
    return [NSString stringWithUTF8String:buffer];
}

static BOOL dx_flag(uint64_t object, const char *selector)
{
    if (!r_is_objc_ptr(object) || !selector) return NO;
    uint64_t sel = r_sel(selector);
    if (!sel) return NO;
    return (r_msg(object, sel, 0, 0, 0, 0) & 0xFF) != 0;
}

@implementation CyanideOverlayDiagnostics

+ (NSString *)collectReport
{
    NSMutableString *report = [NSMutableString string];

    [report appendString:@"== Cyanide 全局悬浮窗自检 ==\n"];
    [report appendFormat:@"krw_ready: %d\n", kexploit_krw_ready() ? 1 : 0];

    if (!kexploit_krw_ready()) {
        BOOL ok = settings_ensure_kernel_ready();
        [report appendFormat:@"ensure_kernel_ready: %d\n", ok ? 1 : 0];
    }

    RemoteCallSession *session =
        [[RemoteCallSession alloc] initWithProcess:@"SpringBoard"
                               useMigFilterBypass:NO
                          firstExceptionTimeoutMS:12000];
    if (!session) {
        [report appendFormat:@"SpringBoard 会话失败: %d\n", (int)remote_call_last_init_failure()];
        return report;
    }
    [report appendFormat:@"SpringBoard pid: %d\n", session.pid];

    __block uint64_t app = 0;
    __block uint64_t windows = 0;
    __block uint64_t countBefore = 0;
    __block uint64_t countAfter = 0;
    __block uint64_t probe = 0;
    __block uint64_t label = 0;
    __block uint64_t labelSuperview = 0;
    __block BOOL probeHidden = YES;
    __block BOOL probeKey = NO;
    __block BOOL labelHidden = YES;
    __block NSString *firstWindowDescription = nil;
    __block NSString *probeDescription = nil;

    uint32_t previousSettle = r_settle_us(0);

    remote_call_with_session(session, ^{
        app = r_msg(r_class("UIApplication"), r_sel("sharedApplication"), 0, 0, 0, 0);
        if (!r_is_objc_ptr(app)) return;

        windows = r_msg(app, r_sel("windows"), 0, 0, 0, 0);
        countBefore = r_is_objc_ptr(windows) ? r_msg(windows, r_sel("count"), 0, 0, 0, 0) : 0;
        if (countBefore > 0 && countBefore < 64) {
            uint64_t firstWindow = r_msg(windows, r_sel("objectAtIndex:"), 0, 0, 0, 0);
            firstWindowDescription = dx_description(firstWindow);
        }

        // 探针窗口：完全照 notepad_tweak 的写法
        CGRect frame = CGRectMake(0.0, 120.0, 260.0, 44.0);
        uint64_t windowAlloc = r_msg(r_class("UIWindow"), r_sel("alloc"), 0, 0, 0, 0);
        probe = r_is_objc_ptr(windowAlloc)
            ? r_msg2_main_raw(windowAlloc, "initWithFrame:", &frame, sizeof(frame),
                              NULL, 0, NULL, 0, NULL, 0)
            : 0;
        if (!r_is_objc_ptr(probe)) return;

        double level = 2000.0;
        r_msg2_main_raw(probe, "setWindowLevel:", &level, sizeof(level), NULL, 0, NULL, 0, NULL, 0);

        uint64_t labelAlloc = r_msg2_main(r_class("UILabel"), "alloc", 0, 0, 0, 0);
        label = r_is_objc_ptr(labelAlloc) ? r_msg2_main(labelAlloc, "init", 0, 0, 0, 0) : 0;
        if (r_is_objc_ptr(label)) {
            CGRect labelFrame = CGRectMake(8.0, 10.0, 240.0, 24.0);
            r_msg2_main_raw(label, "setFrame:", &labelFrame, sizeof(labelFrame),
                            NULL, 0, NULL, 0, NULL, 0);
            uint64_t text = r_nsstr_retained("PROBE 2000");
            if (r_is_objc_ptr(text)) r_msg2_main(label, "setText:", text, 0, 0, 0);
            uint64_t white = r_msg2_main(r_class("UIColor"), "whiteColor", 0, 0, 0, 0);
            if (r_is_objc_ptr(white)) r_msg2_main(label, "setTextColor:", white, 0, 0, 0);
            r_msg2_main(probe, "addSubview:", label, 0, 0, 0);
        }

        r_msg2_main(probe, "setHidden:", 0, 0, 0, 0);
        r_msg2_main(probe, "makeKeyAndVisible", 0, 0, 0, 0);

        probeHidden = dx_flag(probe, "isHidden");
        probeKey = dx_flag(probe, "isKeyWindow");
        if (r_is_objc_ptr(label)) {
            labelSuperview = r_msg(label, r_sel("superview"), 0, 0, 0, 0);
            labelHidden = dx_flag(label, "isHidden");
        }
        countAfter = r_is_objc_ptr(windows) ? r_msg(windows, r_sel("count"), 0, 0, 0, 0) : 0;
        probeDescription = dx_description(probe);
    });

    r_settle_us(previousSettle);

    [report appendFormat:@"UIApplication: 0x%llx\n", app];
    [report appendFormat:@"windows 数量: %llu -> %llu\n",
        (unsigned long long)countBefore, (unsigned long long)countAfter];
    if (firstWindowDescription) {
        [report appendFormat:@"windows[0]: %@\n", firstWindowDescription];
    }

    [report appendString:@"\n-- 探针窗口（notepad_tweak 写法）--\n"];
    if (!r_is_objc_ptr(probe)) {
        [report appendString:@"窗口创建失败\n"];
        return report;
    }
    [report appendFormat:@"window: 0x%llx\n", probe];
    [report appendFormat:@"isHidden: %d   isKeyWindow: %d\n", probeHidden ? 1 : 0, probeKey ? 1 : 0];
    [report appendFormat:@"label: 0x%llx  superview: 0x%llx  hidden: %d\n",
        label, labelSuperview, labelHidden ? 1 : 0];
    if (probeDescription) {
        [report appendFormat:@"描述: %@\n", probeDescription];
    }

    [report appendString:@"\n-- 结论提示 --\n"];
    if (!r_is_objc_ptr(probe)) {
        [report appendString:@"窗口没建出来\n"];
    } else if (countAfter <= countBefore) {
        [report appendString:@"窗口没进 UIApplication.windows —— 创建方式不对\n"];
    } else if (probeHidden) {
        [report appendString:@"窗口在列表里但还是 hidden —— setHidden/makeKeyAndVisible 没生效\n"];
    } else if (!r_is_objc_ptr(labelSuperview)) {
        [report appendString:@"窗口正常但 label 没有父视图 —— addSubview 没生效\n"];
    } else {
        [report appendString:@"窗口和子视图都在位。若屏幕仍看不到，就是层级/场景合成问题（下一步换 scene 或层级）\n"];
    }

    return report;
}

+ (void)presentFrom:(UIViewController *)presenter
{
    if (!presenter) return;

    UIViewController *controller = [[UIViewController alloc] init];
    controller.title = @"悬浮窗自检";
    controller.view.backgroundColor = [UIColor blackColor];

    UITextView *textView = [[UITextView alloc] initWithFrame:controller.view.bounds];
    textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    textView.backgroundColor = [UIColor blackColor];
    textView.textColor = [UIColor colorWithRed:0.6 green:0.95 blue:0.6 alpha:1.0];
    textView.font = [UIFont fontWithName:@"Menlo" size:11.0] ?: [UIFont systemFontOfSize:11.0];
    textView.editable = NO;
    textView.text = @"采集中…";
    [controller.view addSubview:textView];

    UINavigationController *navigation =
        [[UINavigationController alloc] initWithRootViewController:controller];
    navigation.modalPresentationStyle = UIModalPresentationFullScreen;

    [presenter presentViewController:navigation animated:YES completion:^{
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSString *report = [CyanideOverlayDiagnostics collectReport];
            cyanide_log(@"%@", report);
            dispatch_async(dispatch_get_main_queue(), ^{
                textView.text = report;
            });
        });
    }];
}

@end
