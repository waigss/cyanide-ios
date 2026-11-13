//
//  IGDrawList.m
//  Cyanide
//

#import "IGDrawList.h"
#import <CoreText/CoreText.h>
#import <string.h>

static const NSUInteger kIGDrawInitialCapacity = 512;

// 颜色 -> CGColor 缓存。CGColorRef 由字典持有，返回 +0，调用方不要 release。
static CGColorRef IGColorRef(uint32_t color)
{
    static NSMutableDictionary<NSNumber *, id> *cache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cache = [NSMutableDictionary dictionaryWithCapacity:32];
    });

    NSNumber *key = @(color);
    id cached = nil;
    @synchronized (cache) {
        cached = cache[key];
    }
    if (cached) return (__bridge CGColorRef)cached;

    CGFloat a = (CGFloat)((color >> 24) & 0xFF) / 255.0;
    CGFloat r = (CGFloat)((color >> 16) & 0xFF) / 255.0;
    CGFloat g = (CGFloat)((color >> 8) & 0xFF) / 255.0;
    CGFloat b = (CGFloat)(color & 0xFF) / 255.0;
    UIColor *ui = [UIColor colorWithRed:r green:g blue:b alpha:a];
    id value = (__bridge id)ui.CGColor;
    @synchronized (cache) {
        cache[key] = value;
    }
    return (__bridge CGColorRef)value;
}

static CTFontRef IGTextFont(CGFloat fontSize)
{
    // Menlo 是 iOS 自带的等宽字体，和 ImGui 的 ProggyClean 观感最接近。
    CTFontRef font = CTFontCreateWithName(CFSTR("Menlo-Regular"), fontSize, NULL);
    if (!font) font = CTFontCreateWithName(CFSTR("Courier"), fontSize, NULL);
    return font;
}

static CTLineRef IGTextLine(NSString *text, CGFloat fontSize)
{
    if (text.length == 0) return NULL;

    CTFontRef font = IGTextFont(fontSize);
    if (!font) return NULL;

    NSDictionary *attrs = @{
        (__bridge NSString *)kCTFontAttributeName: (__bridge id)font,
    };
    NSAttributedString *attributed = [[NSAttributedString alloc] initWithString:text attributes:attrs];
    CTLineRef line = CTLineCreateWithAttributedString((__bridge CFAttributedStringRef)attributed);
    CFRelease(font);
    return line;
}

CGFloat IGTextWidth(NSString *text, CGFloat fontSize)
{
    if (text.length == 0) return 0.0;
    CTLineRef line = IGTextLine(text, fontSize);
    if (!line) return 0.0;
    CGFloat width = (CGFloat)CTLineGetTypographicBounds(line, NULL, NULL, NULL);
    CFRelease(line);
    return width;
}

static void IGDrawLineText(CGContextRef ctx, const char *utf8, CGPoint origin, CGFloat fontSize, uint32_t color)
{
    if (!utf8 || utf8[0] == '\0') return;

    NSString *text = [NSString stringWithUTF8String:utf8];
    if (text.length == 0) return;

    CTLineRef line = IGTextLine(text, fontSize);
    if (!line) return;

    CGFloat ascent = 0.0, descent = 0.0, leading = 0.0;
    CTLineGetTypographicBounds(line, &ascent, &descent, &leading);
    (void)descent;
    (void)leading;

    CGContextSaveGState(ctx);
    CGContextSetTextMatrix(ctx, CGAffineTransformIdentity);
    CGContextTranslateCTM(ctx, origin.x, origin.y + ascent);
    CGContextScaleCTM(ctx, 1.0, -1.0);
    CGContextSetFillColorWithColor(ctx, IGColorRef(color));
    CTLineDraw(line, ctx);
    CGContextRestoreGState(ctx);

    CFRelease(line);
}

@implementation IGDrawList {
    IGDrawCmd *_cmds;
    NSUInteger _capacity;
    NSUInteger _count;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _capacity = kIGDrawInitialCapacity;
        _cmds = (IGDrawCmd *)calloc(_capacity, sizeof(IGDrawCmd));
        if (!_cmds) {
            _capacity = 0;
            _count = 0;
        }
    }
    return self;
}

- (void)dealloc
{
    free(_cmds);
    _cmds = NULL;
}

- (NSUInteger)count
{
    return _count;
}

- (IGDrawCmd *)reserveCommand
{
    if (!_cmds || _capacity == 0) return NULL;
    if (_count >= _capacity) {
        NSUInteger newCapacity = _capacity * 2;
        IGDrawCmd *grown = (IGDrawCmd *)realloc(_cmds, newCapacity * sizeof(IGDrawCmd));
        if (!grown) return NULL;
        _cmds = grown;
        _capacity = newCapacity;
    }
    IGDrawCmd *cmd = &_cmds[_count];
    memset(cmd, 0, sizeof(IGDrawCmd));
    _count += 1;
    return cmd;
}

- (void)reset
{
    _count = 0;
}

- (void)addLineFrom:(IGVec2)from to:(IGVec2)to color:(uint32_t)color thickness:(CGFloat)thickness
{
    IGDrawCmd *cmd = [self reserveCommand];
    if (!cmd) return;
    cmd->type = IGDrawCmdTypeLine;
    cmd->a = from;
    cmd->b = to;
    cmd->color = color;
    cmd->thickness = MAX(0.5, thickness);
}

- (void)addRect:(CGRect)rect color:(uint32_t)color thickness:(CGFloat)thickness radius:(CGFloat)radius
{
    IGDrawCmd *cmd = [self reserveCommand];
    if (!cmd) return;
    cmd->type = IGDrawCmdTypeRect;
    cmd->a = IGVec2Make(rect.origin.x, rect.origin.y);
    cmd->b = IGVec2Make(rect.size.width, rect.size.height);
    cmd->color = color;
    cmd->thickness = MAX(0.5, thickness);
    cmd->radius = MAX(0.0, radius);
}

- (void)addRectFilled:(CGRect)rect color:(uint32_t)color radius:(CGFloat)radius
{
    IGDrawCmd *cmd = [self reserveCommand];
    if (!cmd) return;
    cmd->type = IGDrawCmdTypeRectFilled;
    cmd->a = IGVec2Make(rect.origin.x, rect.origin.y);
    cmd->b = IGVec2Make(rect.size.width, rect.size.height);
    cmd->color = color;
    cmd->radius = MAX(0.0, radius);
}

- (void)addCircleAt:(IGVec2)center radius:(CGFloat)radius color:(uint32_t)color thickness:(CGFloat)thickness
{
    IGDrawCmd *cmd = [self reserveCommand];
    if (!cmd) return;
    cmd->type = IGDrawCmdTypeCircle;
    cmd->a = center;
    cmd->radius = MAX(0.0, radius);
    cmd->color = color;
    cmd->thickness = MAX(0.5, thickness);
}

- (void)addCircleFilledAt:(IGVec2)center radius:(CGFloat)radius color:(uint32_t)color
{
    IGDrawCmd *cmd = [self reserveCommand];
    if (!cmd) return;
    cmd->type = IGDrawCmdTypeCircleFilled;
    cmd->a = center;
    cmd->radius = MAX(0.0, radius);
    cmd->color = color;
}

- (void)addTriangleFilled:(IGVec2)p0 :(IGVec2)p1 :(IGVec2)p2 color:(uint32_t)color
{
    IGDrawCmd *cmd = [self reserveCommand];
    if (!cmd) return;
    cmd->type = IGDrawCmdTypeTriangleFilled;
    cmd->a = p0;
    cmd->b = p1;
    cmd->c = p2;
    cmd->color = color;
}

- (void)addText:(NSString *)text at:(IGVec2)origin fontSize:(CGFloat)fontSize color:(uint32_t)color
{
    if (text.length == 0) return;
    IGDrawCmd *cmd = [self reserveCommand];
    if (!cmd) return;
    cmd->type = IGDrawCmdTypeText;
    cmd->a = origin;
    cmd->color = color;
    cmd->fontSize = MAX(6.0, fontSize);

    const char *utf8 = text.UTF8String;
    if (!utf8) {
        _count -= 1;
        return;
    }
    size_t maxBytes = sizeof(cmd->text) - 1;
    size_t length = strnlen(utf8, maxBytes);
    memcpy(cmd->text, utf8, length);
    cmd->text[length] = '\0';
}

- (UIImage *)renderWithSize:(CGSize)size scale:(CGFloat)scale
{
    return [self renderWithSize:size scale:scale translate:IGVec2Make(0.0, 0.0)];
}

- (UIImage *)renderWithSize:(CGSize)size scale:(CGFloat)scale translate:(IGVec2)offset
{
    if (size.width < 1.0 || size.height < 1.0) return nil;
    if (scale <= 0.0) scale = 1.0;

    UIGraphicsImageRendererFormat *format = [UIGraphicsImageRendererFormat defaultFormat];
    format.opaque = NO;
    format.scale = scale;

    UIGraphicsImageRenderer *renderer =
        [[UIGraphicsImageRenderer alloc] initWithSize:size format:format];

    return [renderer imageWithActions:^(UIGraphicsImageRendererContext *rendererContext) {
        CGContextRef ctx = rendererContext.CGContext;
        CGContextSetShouldAntialias(ctx, true);
        CGContextSetLineJoin(ctx, kCGLineJoinRound);
        CGContextSetLineCap(ctx, kCGLineCapRound);

        if (offset.x != 0.0 || offset.y != 0.0) {
            CGContextTranslateCTM(ctx, -offset.x, -offset.y);
        }

        for (NSUInteger i = 0; i < self->_count; i++) {
            const IGDrawCmd *cmd = &self->_cmds[i];
            switch (cmd->type) {
                case IGDrawCmdTypeLine: {
                    CGContextSetStrokeColorWithColor(ctx, IGColorRef(cmd->color));
                    CGContextSetLineWidth(ctx, cmd->thickness);
                    CGContextMoveToPoint(ctx, cmd->a.x, cmd->a.y);
                    CGContextAddLineToPoint(ctx, cmd->b.x, cmd->b.y);
                    CGContextStrokePath(ctx);
                    break;
                }
                case IGDrawCmdTypeRect: {
                    CGRect rect = CGRectMake(cmd->a.x, cmd->a.y, cmd->b.x, cmd->b.y);
                    CGContextSetStrokeColorWithColor(ctx, IGColorRef(cmd->color));
                    CGContextSetLineWidth(ctx, cmd->thickness);
                    if (cmd->radius > 0.5) {
                        CGPathRef path = CGPathCreateWithRoundedRect(rect, cmd->radius, cmd->radius, NULL);
                        CGContextAddPath(ctx, path);
                        CGContextStrokePath(ctx);
                        CGPathRelease(path);
                    } else {
                        CGContextStrokeRect(ctx, rect);
                    }
                    break;
                }
                case IGDrawCmdTypeRectFilled: {
                    CGRect rect = CGRectMake(cmd->a.x, cmd->a.y, cmd->b.x, cmd->b.y);
                    CGContextSetFillColorWithColor(ctx, IGColorRef(cmd->color));
                    if (cmd->radius > 0.5) {
                        CGPathRef path = CGPathCreateWithRoundedRect(rect, cmd->radius, cmd->radius, NULL);
                        CGContextAddPath(ctx, path);
                        CGContextFillPath(ctx);
                        CGPathRelease(path);
                    } else {
                        CGContextFillRect(ctx, rect);
                    }
                    break;
                }
                case IGDrawCmdTypeCircle: {
                    CGRect rect = CGRectMake(cmd->a.x - cmd->radius, cmd->a.y - cmd->radius,
                                             cmd->radius * 2.0, cmd->radius * 2.0);
                    CGContextSetStrokeColorWithColor(ctx, IGColorRef(cmd->color));
                    CGContextSetLineWidth(ctx, cmd->thickness);
                    CGContextStrokeEllipseInRect(ctx, rect);
                    break;
                }
                case IGDrawCmdTypeCircleFilled: {
                    CGRect rect = CGRectMake(cmd->a.x - cmd->radius, cmd->a.y - cmd->radius,
                                             cmd->radius * 2.0, cmd->radius * 2.0);
                    CGContextSetFillColorWithColor(ctx, IGColorRef(cmd->color));
                    CGContextFillEllipseInRect(ctx, rect);
                    break;
                }
                case IGDrawCmdTypeTriangleFilled: {
                    CGContextSetFillColorWithColor(ctx, IGColorRef(cmd->color));
                    CGContextMoveToPoint(ctx, cmd->a.x, cmd->a.y);
                    CGContextAddLineToPoint(ctx, cmd->b.x, cmd->b.y);
                    CGContextAddLineToPoint(ctx, cmd->c.x, cmd->c.y);
                    CGContextClosePath(ctx);
                    CGContextFillPath(ctx);
                    break;
                }
                case IGDrawCmdTypeText: {
                    IGDrawLineText(ctx, cmd->text, CGPointMake(cmd->a.x, cmd->a.y), cmd->fontSize, cmd->color);
                    break;
                }
            }
        }
    }];
}

@end
