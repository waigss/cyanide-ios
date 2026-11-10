//
//  notepad_tweak.m
//  Cyanide -- floating notepad panel inside SpringBoard.
//
//  Ported to the current remote_objc.h API. The previous revision of this file
//  still called the removed helpers r_objc_getClass / r_msg2_ptr /
//  r_sel_registerName and passed arguments in the old variadic shape, so it did
//  not compile against a current Xcode (implicit function declarations are hard
//  errors since Clang 16). Semantics are unchanged; only the call convention
//  was updated:
//
//      r_objc_getClass(x)              -> r_class(x)
//      r_sel_registerName(x)           -> r_sel(x)          (interned pointer)
//      r_msg2_ptr(o, sel, a0, a1)      -> r_msg2(o, sel, a0, a1, 0, 0)
//      r_msg2_main(o, sel, n, a...)    -> r_msg2_main(o, sel, a0, 0, 0, 0)
//      doubles / CGRects               -> r_msg2_main_raw(o, sel, &v, sizeof(v), ...)
//      struct return (CGRect)          -> r_msg2_main_struct_ret(...)
//      r_dlsym_call(name, n, a...)     -> r_dlsym_call(R_TIMEOUT, name, a0..a7)
//

#import "notepad_tweak.h"
#import "remote_objc.h"
#import "../TaskRop/RemoteCall.h"
#import <objc/runtime.h>
#import <CoreGraphics/CoreGraphics.h>

#define NP_LABEL_TAG 1337
#define NP_ASSOC_KEY "cyanideNotepadWindow"
#define NP_OBJC_ASSOCIATION_RETAIN_NONATOMIC 1

static uint64_t g_remote_window = 0;

// objc_msgSend in the target process (off the main thread), no arguments.
static uint64_t np_msg(uint64_t obj, const char *selName)
{
    if (!r_is_objc_ptr(obj)) return 0;
    return r_msg2(obj, selName, 0, 0, 0, 0);
}

// objc_msgSend in the target process with one pointer/integer argument.
static uint64_t np_msg1(uint64_t obj, const char *selName, uint64_t a0)
{
    if (!r_is_objc_ptr(obj)) return 0;
    return r_msg2(obj, selName, a0, 0, 0, 0);
}

// objc_msgSend on the target's main thread, one pointer/integer argument.
static void np_msg_main(uint64_t obj, const char *selName, uint64_t a0)
{
    if (!r_is_objc_ptr(obj)) return;
    r_msg2_main(obj, selName, a0, 0, 0, 0);
}

// CGFloat / double argument (passed by value, so hand over the raw bytes).
static void np_msg_main_double(uint64_t obj, const char *selName, double value)
{
    if (!r_is_objc_ptr(obj)) return;
    r_msg2_main_raw(obj, selName, &value, sizeof(value), NULL, 0, NULL, 0, NULL, 0);
}

bool notepad_tweak_apply_in_session(NSString *text)
{
    if (!text) text = @"Hello from Cyanide!";

    uint64_t app = np_msg(r_class("UIApplication"), "sharedApplication");
    if (!r_is_objc_ptr(app)) return false;

    // The panel is kept alive by an associated object on UIApplication, so a
    // second apply reuses the existing window instead of stacking a new one.
    // The key must be the *interned* selector pointer, hence r_sel().
    uint64_t assocKey = r_sel(NP_ASSOC_KEY);
    g_remote_window = r_dlsym_call(R_TIMEOUT, "objc_getAssociatedObject",
                                   app, assocKey, 0, 0, 0, 0, 0, 0);

    if (!r_is_objc_ptr(g_remote_window)) {
        uint64_t windowAlloc = np_msg(r_class("UIWindow"), "alloc");
        if (!r_is_objc_ptr(windowAlloc)) return false;

        uint64_t screen = np_msg(r_class("UIScreen"), "mainScreen");
        CGRect bounds = CGRectZero;
        if (r_is_objc_ptr(screen)) {
            r_msg2_main_struct_ret(screen, "bounds",
                                   &bounds, sizeof(bounds),
                                   NULL, 0, NULL, 0, NULL, 0, NULL, 0);
        }
        if (bounds.size.width <= 1.0) bounds = CGRectMake(0, 0, 390, 844);

        CGRect frame = CGRectMake(20, 100, bounds.size.width - 40, 100);
        g_remote_window = r_msg2_main_raw(windowAlloc, "initWithFrame:",
                                          &frame, sizeof(frame),
                                          NULL, 0, NULL, 0, NULL, 0);
        if (!r_is_objc_ptr(g_remote_window)) {
            g_remote_window = 0;
            return false;
        }

        // Above UIWindowLevelStatusBar (1000) so the panel floats over SpringBoard.
        np_msg_main_double(g_remote_window, "setWindowLevel:", 2000.0);

        uint64_t uiColorClass = r_class("UIColor");
        double white = 0.0;
        double alpha = 0.5;
        uint64_t color = r_msg2_main_raw(uiColorClass, "colorWithWhite:alpha:",
                                         &white, sizeof(white),
                                         &alpha, sizeof(alpha),
                                         NULL, 0, NULL, 0);
        np_msg_main(g_remote_window, "setBackgroundColor:", color);

        uint64_t layer = np_msg(g_remote_window, "layer");
        np_msg_main_double(layer, "setCornerRadius:", 15.0);
        np_msg_main(layer, "setMasksToBounds:", 1);

        uint64_t label = np_msg(r_class("UILabel"), "alloc");
        CGRect labelFrame = CGRectMake(10, 10,
                                       frame.size.width - 20, frame.size.height - 20);
        label = r_msg2_main_raw(label, "initWithFrame:",
                                &labelFrame, sizeof(labelFrame),
                                NULL, 0, NULL, 0, NULL, 0);

        np_msg_main(label, "setNumberOfLines:", 0);
        np_msg_main(label, "setTextAlignment:", 1); // NSTextAlignmentCenter
        np_msg_main(label, "setTextColor:", np_msg(uiColorClass, "whiteColor"));

        double fontSize = 16.0;
        double fontWeight = 0.0; // UIFontWeightRegular
        uint64_t font = r_msg2_main_raw(r_class("UIFont"), "systemFontOfSize:weight:",
                                        &fontSize, sizeof(fontSize),
                                        &fontWeight, sizeof(fontWeight),
                                        NULL, 0, NULL, 0);
        np_msg_main(label, "setFont:", font);

        np_msg_main(label, "setTag:", NP_LABEL_TAG);
        np_msg_main(g_remote_window, "addSubview:", label);

        r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject",
                     app, assocKey, g_remote_window,
                     NP_OBJC_ASSOCIATION_RETAIN_NONATOMIC, 0, 0, 0, 0);
    }

    uint64_t label = np_msg1(g_remote_window, "viewWithTag:", NP_LABEL_TAG);
    if (r_is_objc_ptr(label)) {
        uint64_t remoteText = r_alloc_str([text UTF8String]);
        if (remoteText) {
            np_msg_main(label, "setText:", remoteText);
            r_free(remoteText);
        }
    }

    np_msg_main(g_remote_window, "setHidden:", 0);
    r_msg2_main(g_remote_window, "makeKeyAndVisible", 0, 0, 0, 0);

    return true;
}

void notepad_tweak_stop_in_session(void)
{
    uint64_t app = np_msg(r_class("UIApplication"), "sharedApplication");
    if (!r_is_objc_ptr(app)) return;

    uint64_t assocKey = r_sel(NP_ASSOC_KEY);
    uint64_t window = r_dlsym_call(R_TIMEOUT, "objc_getAssociatedObject",
                                   app, assocKey, 0, 0, 0, 0, 0, 0);
    if (r_is_objc_ptr(window)) {
        np_msg_main(window, "setHidden:", 1);
        // Dropping the association releases the panel.
        r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject",
                     app, assocKey, 0, NP_OBJC_ASSOCIATION_RETAIN_NONATOMIC, 0, 0, 0, 0);
    }
    g_remote_window = 0;
}

void notepad_tweak_forget_remote_state(void)
{
    g_remote_window = 0;
}
