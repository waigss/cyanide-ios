#import "notepad_tweak.h"
#import "remote_objc.h"
#import "../TaskRop/RemoteCall.h"
#import <objc/runtime.h>

static uint64_t g_remote_window = 0;

bool notepad_tweak_apply_in_session(NSString *text) {
    if (!text) text = @"Hello from Cyanide!";
    
    // Get UIApplication sharedApplication
    uint64_t uiAppClass = r_objc_getClass("UIApplication");
    uint64_t app = r_msg2_ptr(uiAppClass, r_sel_registerName("sharedApplication"));
    if (!app) return false;

    // Try to get existing window from associated object
    const char *assocKey = "cyanideNotepadWindow";
    g_remote_window = r_dlsym_call("objc_getAssociatedObject", 2, app, r_sel_registerName(assocKey));

    if (!g_remote_window) {
        // Create new UIWindow
        uint64_t windowClass = r_objc_getClass("UIWindow");
        g_remote_window = r_msg2_ptr(windowClass, r_sel_registerName("alloc"));
        
        // UIScreen mainScreen bounds
        uint64_t screenClass = r_objc_getClass("UIScreen");
        uint64_t screen = r_msg2_ptr(screenClass, r_sel_registerName("mainScreen"));
        CGRect bounds;
        r_msg2_main_raw(screen, r_sel_registerName("bounds"), 0, NULL, &bounds, sizeof(bounds));
        
        // window = [window initWithFrame:CGRectMake(20, 100, bounds.size.width - 40, 100)]
        CGRect frame = CGRectMake(20, 100, bounds.size.width - 40, 100);
        r_msg2_main_raw(g_remote_window, r_sel_registerName("initWithFrame:"), 1, &frame, &g_remote_window, sizeof(g_remote_window));
        
        // window.windowLevel = 2000 (UIWindowLevelStatusBar + 1)
        double level = 2000.0;
        r_msg2_main(g_remote_window, r_sel_registerName("setWindowLevel:"), 1, level);
        
        // window.backgroundColor = [UIColor colorWithWhite:0 alpha:0.5]
        uint64_t uiColorClass = r_objc_getClass("UIColor");
        uint64_t color = r_msg2_ptr(uiColorClass, r_sel_registerName("colorWithWhite:alpha:"), 0.0, 0.5);
        r_msg2_main(g_remote_window, r_sel_registerName("setBackgroundColor:"), 1, color);
        
        // window.layer.cornerRadius = 15
        uint64_t layer = r_msg2_ptr(g_remote_window, r_sel_registerName("layer"));
        r_msg2_main(layer, r_sel_registerName("setCornerRadius:"), 1, 15.0);
        r_msg2_main(layer, r_sel_registerName("setMasksToBounds:"), 1, (bool)true);

        // Create UILabel
        uint64_t labelClass = r_objc_getClass("UILabel");
        uint64_t label = r_msg2_ptr(labelClass, r_sel_registerName("alloc"));
        CGRect labelFrame = CGRectMake(10, 10, frame.size.width - 20, frame.size.height - 20);
        r_msg2_main_raw(label, r_sel_registerName("initWithFrame:"), 1, &labelFrame, &label, sizeof(label));
        
        r_msg2_main(label, r_sel_registerName("setNumberOfLines:"), 1, (int)0);
        r_msg2_main(label, r_sel_registerName("setTextAlignment:"), 1, (int)1); // Center
        uint64_t whiteColor = r_msg2_ptr(uiColorClass, r_sel_registerName("whiteColor"));
        r_msg2_main(label, r_sel_registerName("setTextColor:"), 1, whiteColor);
        
        uint64_t fontClass = r_objc_getClass("UIFont");
        uint64_t font = r_msg2_ptr(fontClass, r_sel_registerName("systemFontOfSize:weight:"), 16.0, 0.0);
        r_msg2_main(label, r_sel_registerName("setFont:"), 1, font);
        
        r_msg2_main(label, r_sel_registerName("setTag:"), 1, (int)1337);
        r_msg2_main(g_remote_window, r_sel_registerName("addSubview:"), 1, label);

        // Store window in associated object
        r_dlsym_call("objc_setAssociatedObject", 4, app, r_sel_registerName(assocKey), g_remote_window, 1); // OBJC_ASSOCIATION_RETAIN_NONATOMIC
    }

    // Update text
    uint64_t label = r_msg2_ptr(g_remote_window, r_sel_registerName("viewWithTag:"), 1337);
    if (label) {
        uint64_t r_text = r_alloc_str([text UTF8String]);
        r_msg2_main(label, r_sel_registerName("setText:"), 1, r_text);
        r_free(r_text);
    }

    // Show window
    r_msg2_main(g_remote_window, r_sel_registerName("setHidden:"), 1, (bool)false);
    r_msg2_main(g_remote_window, r_sel_registerName("makeKeyAndVisible"), 0);

    return true;
}

void notepad_tweak_stop_in_session(void) {
    uint64_t uiAppClass = r_objc_getClass("UIApplication");
    uint64_t app = r_msg2_ptr(uiAppClass, r_sel_registerName("sharedApplication"));
    if (!app) return;

    const char *assocKey = "cyanideNotepadWindow";
    uint64_t window = r_dlsym_call("objc_getAssociatedObject", 2, app, r_sel_registerName(assocKey));
    
    if (window) {
        r_msg2_main(window, r_sel_registerName("setHidden:"), 1, (bool)true);
        // Clear associated object
        r_dlsym_call("objc_setAssociatedObject", 4, app, r_sel_registerName(assocKey), (uint64_t)0, 1);
    }
    g_remote_window = 0;
}

void notepad_tweak_forget_remote_state(void) {
    g_remote_window = 0;
}
