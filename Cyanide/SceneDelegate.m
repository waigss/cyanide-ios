//
//  SceneDelegate.m
//  Cyanide
//
//  Created by seo on 3/24/26.
//

#import "SceneDelegate.h"
#import "SettingsViewController.h"
#import "UpdateChecker.h"
#import "inspector/ProcessListViewController.h"
#import "inspector/CyanideLog.h"
#import <sys/utsname.h>

@interface SceneDelegate ()
@property (nonatomic, assign) BOOL didSelectInitialTab;

@end

@implementation SceneDelegate


- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions {
    struct utsname info;
    memset(&info, 0, sizeof(info));
    uname(&info);
    cyanide_log(@"==== Cyanide 启动：iOS %@ 机型 %s 版本 %@ ====",
         UIDevice.currentDevice.systemVersion,
         info.machine,
         [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"?");

    // 精简版：不要 TabBar / 安装器 / 设置页，启动直接进「进程」页。
    UIViewController *root = self.window.rootViewController;
    if (root) {
        ProcessListViewController *list =
            [[ProcessListViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
        UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:list];
        nav.navigationBar.prefersLargeTitles = NO;
        self.window.rootViewController = nav;
    }
}

- (void)selectInitialTabIfNeeded {
    if (self.didSelectInitialTab) return;
    UITabBarController *tab = (UITabBarController *)self.window.rootViewController;
    if (![tab isKindOfClass:UITabBarController.class] || tab.viewControllers.count == 0) return;
    self.didSelectInitialTab = YES;
    tab.selectedIndex = 0; // Installer tab
}


- (void)sceneDidDisconnect:(UIScene *)scene {
    // Called as the scene is being released by the system.
    // This occurs shortly after the scene enters the background, or when its session is discarded.
    // Release any resources associated with this scene that can be re-created the next time the scene connects.
    // The scene may re-connect later, as its session was not necessarily discarded (see `application:didDiscardSceneSessions` instead).
}


- (void)runUpdateCheck {
    UITabBarController *tab = (UITabBarController *)self.window.rootViewController;
    if (![tab isKindOfClass:UITabBarController.class]) return;
    // UpdateChecker walks `presentedViewController` to find the topmost VC and
    // presents from there, so if the privacy alert is up, the update prompt
    // stacks on top — independent of consent state.
    [[UpdateChecker shared] checkForUpdatesIfNeededFrom:tab];
}

- (void)showLogCollectionOptInNoticeIfNeeded {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *noticeKey = @"cyanide.privacy.logOptInDefaultNoticeShown";
    if ([ud boolForKey:noticeKey]) return;

    [ud setBool:NO forKey:kSettingsLogUploadEnabled];
    [ud synchronize];

    UIViewController *root = self.window.rootViewController;
    if (!root) return;
    NSString *msg = @"Automatic log collection is now off by default. Diagnostic uploads are opt-in only.\n\nYou can turn them on anytime in Settings > About > Auto-Upload Logs. When enabled, Cyanide uploads chain stage timing, error messages, device model, and iOS version after a run. Logs go to a private Cloudflare R2 bucket owned by @zeroxjf and expire after 30 days.";
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Log Collection Is Opt-In"
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        [ud setBool:YES forKey:noticeKey];
        [ud setBool:YES forKey:@"cyanide.privacy.logConsentShown"];
        [ud synchronize];
    }]];
    [root presentViewController:alert animated:YES completion:nil];
}

- (void)sceneDidBecomeActive:(UIScene *)scene {
    [self selectInitialTabIfNeeded];
    settings_application_did_become_active();
    // Independent paths: log collection opt-in notice (one-time) and update
    // check (every foreground; UpdateChecker enforces a per-process + 24-hour
    // persisted throttle so the API isn't hammered).
    // The two can stack on first launch — that's intentional, an available
    // update shouldn't be hidden behind a privacy preference.
    [self showLogCollectionOptInNoticeIfNeeded];
    [self runUpdateCheck];
}


- (void)sceneWillResignActive:(UIScene *)scene {
    // Called when the scene will move from an active state to an inactive state.
    // This may occur due to temporary interruptions (ex. an incoming phone call).
}


- (void)sceneWillEnterForeground:(UIScene *)scene {
    settings_application_will_enter_foreground();
}


- (void)sceneDidEnterBackground:(UIScene *)scene {
    settings_application_did_enter_background();
}


@end
