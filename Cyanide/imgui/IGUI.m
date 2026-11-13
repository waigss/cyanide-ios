//
//  IGUI.m
//  Cyanide
//

#import "IGUI.h"

IGStyle IGStyleDefault(void)
{
    IGStyle s;
    memset(&s, 0, sizeof(s));

    // ImGui 默认暗色主题（imgui_draw.cpp StyleColorsDark）转换成 0xAARRGGBB
    s.colWindowBg         = 0xF00F0F0F;
    s.colTitleBg          = 0xFF0A0A0A;
    s.colTitleBgActive    = 0xFF294A7A;
    s.colBorder           = 0x806E6E80;
    s.colFrameBg          = 0x8A294A7A;
    s.colFrameBgHovered   = 0x664296FA;
    s.colCheckMark        = 0xFF4296FA;
    s.colText             = 0xFFFFFFFF;
    s.colTextDisabled     = 0xFF808080;
    s.colSeparator        = 0x806E6E80;
    s.colSliderGrab       = 0xFF3D85E0;
    s.colSliderGrabActive = 0xFF4296FA;
    s.colButton           = 0x664296FA;
    s.colButtonHovered    = 0xBF4296FA;
    s.colTab              = 0x4F4296FA;
    s.colTabActive        = 0xA84296FA;

    // ImGui 默认度量（Style 结构里的 WindowPadding / FramePadding / ItemSpacing）
    s.windowPaddingX = 8.0;
    s.windowPaddingY = 8.0;
    s.itemSpacingY   = 5.0;
    s.fontSize       = 12.0;
    s.titleHeight    = 24.0;
    s.windowRounding = 6.0;
    s.frameRounding  = 3.0;
    s.borderSize     = 1.0;
    s.sliderHeight   = 18.0;
    s.grabWidth      = 9.0;
    s.checkboxSize   = 15.0;
    s.buttonHeight   = 22.0;
    s.tabHeight      = 20.0;
    return s;
}

@implementation IGUI {
    CGFloat _cursorY;
    CGFloat _contentHeight;
    CGRect _windowFrame;
    BOOL _measuring;
    BOOL _insideWindow;
    CGSize _displaySize;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _drawList = [[IGDrawList alloc] init];
        _style = IGStyleDefault();
        _lastItemRect = CGRectZero;
    }
    return self;
}

#pragma mark - 帧

- (void)beginFrameWithDisplaySize:(CGSize)size
{
    _displaySize = size;
    _measuring = NO;
    _insideWindow = NO;
    _contentHeight = 0.0;
    _cursorY = 0.0;
    _windowFrame = CGRectZero;
    _lastItemRect = CGRectZero;
    [self.drawList reset];
}

- (void)endFrame
{
    _insideWindow = NO;
}

- (CGFloat)measureWithWidth:(CGFloat)width build:(void (^)(void))build
{
    if (!build) return 0.0;

    BOOL previousMeasuring = _measuring;
    CGRect previousFrame = _windowFrame;
    CGFloat previousCursor = _cursorY;

    _measuring = YES;
    _windowFrame = CGRectMake(0.0, 0.0, width, 0.0);
    _cursorY = 0.0;

    build();

    CGFloat height = _cursorY;

    _measuring = previousMeasuring;
    _windowFrame = previousFrame;
    _cursorY = previousCursor;
    return height;
}

#pragma mark - 布局小工具

- (CGFloat)innerX
{
    return _windowFrame.origin.x + self.style.windowPaddingX;
}

- (CGFloat)innerWidth
{
    CGFloat w = _windowFrame.size.width - self.style.windowPaddingX * 2.0;
    return MAX(16.0, w);
}

- (CGFloat)lineHeight
{
    return self.style.fontSize + 4.0;
}

- (void)fillRect:(CGRect)rect color:(uint32_t)color radius:(CGFloat)radius
{
    if (_measuring) return;
    [self.drawList addRectFilled:rect color:color radius:radius];
}

- (void)strokeRect:(CGRect)rect color:(uint32_t)color thickness:(CGFloat)thickness radius:(CGFloat)radius
{
    if (_measuring) return;
    [self.drawList addRect:rect color:color thickness:thickness radius:radius];
}

- (void)drawText:(NSString *)text at:(CGPoint)point color:(uint32_t)color fontScale:(CGFloat)scale
{
    if (_measuring || text.length == 0) return;
    [self.drawList addText:text
                        at:IGVec2Make(point.x, point.y)
                  fontSize:self.style.fontSize * scale
                     color:color];
}

#pragma mark - 窗口

- (void)beginWindow:(NSString *)title frame:(CGRect)frame
{
    _insideWindow = YES;
    _windowFrame = frame;

    if (!_measuring) {
        CGFloat rounding = self.style.windowRounding;
        [self.drawList addRectFilled:frame color:self.style.colWindowBg radius:rounding];

        // 标题栏：先画圆角整条，再补一块直角下半段，避免底部出现圆角缺口。
        CGRect titleRect = CGRectMake(frame.origin.x, frame.origin.y,
                                      frame.size.width, self.style.titleHeight);
        [self.drawList addRectFilled:titleRect color:self.style.colTitleBgActive radius:rounding];
        if (self.style.titleHeight > rounding + 2.0) {
            CGRect lower = CGRectMake(titleRect.origin.x,
                                      CGRectGetMaxY(titleRect) - rounding - 1.0,
                                      titleRect.size.width,
                                      rounding + 1.0);
            [self.drawList addRectFilled:lower color:self.style.colTitleBgActive radius:0.0];
        }

        CGPoint titleOrigin = CGPointMake(frame.origin.x + self.style.windowPaddingX,
                                          frame.origin.y + (self.style.titleHeight - self.style.fontSize) / 2.0 - 1.0);
        [self.drawList addText:title
                            at:IGVec2Make(titleOrigin.x, titleOrigin.y)
                      fontSize:self.style.fontSize + 1.0
                         color:self.style.colText];

        [self.drawList addRect:frame color:self.style.colBorder thickness:self.style.borderSize radius:rounding];
    }

    _cursorY = frame.origin.y + self.style.titleHeight + self.style.windowPaddingY;
    _contentHeight = 0.0;
}

- (void)endWindow
{
    if (_insideWindow) {
        _contentHeight = _cursorY - (_windowFrame.origin.y + self.style.titleHeight + self.style.windowPaddingY);
        _cursorY += self.style.windowPaddingY;
    }
    _insideWindow = NO;
}

#pragma mark - 控件

- (void)text:(NSString *)text
{
    [self textColored:self.style.colText text:text];
}

- (void)textDisabled:(NSString *)text
{
    [self textColored:self.style.colTextDisabled text:text];
}

- (void)textColored:(uint32_t)color text:(NSString *)text
{
    CGFloat height = [self lineHeight];
    [self drawText:text at:CGPointMake([self innerX], _cursorY + 1.0) color:color fontScale:1.0];
    _lastItemRect = CGRectMake([self innerX], _cursorY, [self innerWidth], height);
    _cursorY += height + self.style.itemSpacingY;
}

- (void)separator
{
    if (!_measuring) {
        CGFloat y = _cursorY + 3.0;
        [self.drawList addLineFrom:IGVec2Make([self innerX], y)
                                to:IGVec2Make([self innerX] + [self innerWidth], y)
                             color:self.style.colSeparator
                         thickness:1.0];
    }
    _cursorY += 7.0 + self.style.itemSpacingY;
}

- (void)checkbox:(NSString *)label value:(BOOL)value
{
    CGFloat box = self.style.checkboxSize;
    CGFloat height = MAX(20.0, box + 5.0);
    CGFloat x = [self innerX];
    CGFloat width = [self innerWidth];

    CGRect boxRect = CGRectMake(x, _cursorY + (height - box) / 2.0, box, box);
    [self fillRect:boxRect color:self.style.colFrameBg radius:2.0];
    [self strokeRect:boxRect color:self.style.colBorder thickness:1.0 radius:2.0];

    if (value && !_measuring) {
        [self.drawList addLineFrom:IGVec2Make(boxRect.origin.x + 3.5, boxRect.origin.y + box * 0.52)
                                to:IGVec2Make(boxRect.origin.x + box * 0.42, boxRect.origin.y + box - 4.0)
                             color:self.style.colCheckMark
                         thickness:2.0];
        [self.drawList addLineFrom:IGVec2Make(boxRect.origin.x + box * 0.42, boxRect.origin.y + box - 4.0)
                                to:IGVec2Make(boxRect.origin.x + box - 3.0, boxRect.origin.y + 3.5)
                             color:self.style.colCheckMark
                         thickness:2.0];
    }

    CGFloat labelHeight = self.style.fontSize;
    [self drawText:label
                at:CGPointMake(CGRectGetMaxX(boxRect) + 8.0, _cursorY + (height - labelHeight) / 2.0)
               color:value ? self.style.colText : self.style.colTextDisabled
           fontScale:1.0];

    _lastItemRect = CGRectMake(x, _cursorY, width, height);
    _cursorY += height + self.style.itemSpacingY;
}

- (void)sliderFloat:(NSString *)label
              value:(CGFloat)value
                min:(CGFloat)min
                max:(CGFloat)max
          valueText:(NSString *)valueText
{
    CGFloat x = [self innerX];
    CGFloat width = [self innerWidth];
    CGFloat labelHeight = [self lineHeight];

    [self drawText:label at:CGPointMake(x, _cursorY) color:self.style.colText fontScale:1.0];

    if (!_measuring && valueText.length > 0) {
        CGFloat valueWidth = IGTextWidth(valueText, self.style.fontSize);
        [self.drawList addText:valueText
                            at:IGVec2Make(x + width - valueWidth, _cursorY)
                      fontSize:self.style.fontSize
                         color:self.style.colTextDisabled];
    }

    CGFloat trackY = _cursorY + labelHeight;
    CGFloat trackH = self.style.sliderHeight;
    CGRect track = CGRectMake(x, trackY, width, trackH);

    CGFloat range = (max - min);
    CGFloat fraction = (range > 0.0) ? (value - min) / range : 0.0;
    fraction = MAX(0.0, MIN(1.0, fraction));

    [self fillRect:track color:self.style.colFrameBg radius:self.style.frameRounding];

    CGFloat grabW = self.style.grabWidth;
    CGFloat filledW = MAX(grabW, fraction * width);
    if (!_measuring) {
        [self.drawList addRectFilled:CGRectMake(x, trackY, filledW, trackH)
                               color:IGColorAlpha(self.style.colSliderGrab, 0.55)
                              radius:self.style.frameRounding];
        CGFloat grabX = x + fraction * (width - grabW);
        [self.drawList addRectFilled:CGRectMake(grabX, trackY, grabW, trackH)
                               color:self.style.colSliderGrab
                              radius:self.style.frameRounding];
    }

    _lastItemRect = CGRectMake(x, _cursorY, width, labelHeight + trackH);
    _cursorY += labelHeight + trackH + self.style.itemSpacingY;
}

- (void)sliderIntTicks:(NSString *)label
                 value:(NSInteger)value
                   min:(NSInteger)min
                   max:(NSInteger)max
             valueText:(NSString *)valueText
{
    CGFloat x = [self innerX];
    CGFloat width = [self innerWidth];
    CGFloat labelHeight = [self lineHeight];
    CGFloat trackH = self.style.sliderHeight;

    [self drawText:label at:CGPointMake(x, _cursorY) color:self.style.colText fontScale:1.0];

    if (!_measuring && valueText.length > 0) {
        CGFloat valueWidth = IGTextWidth(valueText, self.style.fontSize);
        [self.drawList addText:valueText
                            at:IGVec2Make(x + width - valueWidth, _cursorY)
                      fontSize:self.style.fontSize
                         color:self.style.colTextDisabled];
    }

    CGFloat trackY = _cursorY + labelHeight;
    CGRect track = CGRectMake(x, trackY, width, trackH);
    [self fillRect:track color:self.style.colFrameBg radius:self.style.frameRounding];

    NSInteger steps = MAX((NSInteger)1, max - min);
    CGFloat fraction = (CGFloat)(value - min) / (CGFloat)steps;
    fraction = MAX(0.0, MIN(1.0, fraction));

    CGFloat grabW = self.style.grabWidth;

    if (!_measuring) {
        [self.drawList addRectFilled:CGRectMake(x, trackY, MAX(grabW, fraction * width), trackH)
                               color:IGColorAlpha(self.style.colSliderGrab, 0.55)
                              radius:self.style.frameRounding];

        // 每一档一根短刻度，提示这是分段选择而不是连续拖动。
        for (NSInteger i = 0; i <= steps; i++) {
            CGFloat tickX = x + width * (CGFloat)i / (CGFloat)steps;
            tickX = MIN(MAX(tickX, x + 1.0), x + width - 1.0);
            [self.drawList addRectFilled:CGRectMake(tickX - 0.5, trackY + trackH - 4.0, 1.0, 3.0)
                                   color:IGColorAlpha(self.style.colText, 0.30)
                                  radius:0.0];
        }

        CGFloat grabX = x + fraction * (width - grabW);
        [self.drawList addRectFilled:CGRectMake(grabX, trackY, grabW, trackH)
                               color:self.style.colSliderGrab
                              radius:self.style.frameRounding];
    }

    _lastItemRect = CGRectMake(x, _cursorY, width, labelHeight + trackH);
    _cursorY += labelHeight + trackH + self.style.itemSpacingY;
}

- (void)button:(NSString *)label
{
    CGFloat x = [self innerX];
    CGFloat width = [self innerWidth];
    CGFloat height = self.style.buttonHeight;
    CGRect rect = CGRectMake(x, _cursorY, width, height);

    [self fillRect:rect color:self.style.colButton radius:self.style.frameRounding];
    [self strokeRect:rect color:self.style.colBorder thickness:1.0 radius:self.style.frameRounding];

    if (!_measuring) {
        CGFloat textWidth = IGTextWidth(label, self.style.fontSize);
        [self.drawList addText:label
                            at:IGVec2Make(x + (width - textWidth) / 2.0,
                                          _cursorY + (height - self.style.fontSize) / 2.0 - 0.5)
                      fontSize:self.style.fontSize
                         color:self.style.colText];
    }

    _lastItemRect = rect;
    _cursorY += height + self.style.itemSpacingY;
}

- (void)tabBar:(NSArray<NSString *> *)labels active:(NSInteger)active
{
    NSUInteger count = labels.count;
    if (count == 0) return;

    CGFloat x = [self innerX];
    CGFloat width = [self innerWidth];
    CGFloat height = self.style.tabHeight;
    CGFloat cellWidth = width / (CGFloat)count;

    for (NSUInteger i = 0; i < count; i++) {
        BOOL isActive = ((NSInteger)i == active);
        CGRect cell = CGRectMake(x + cellWidth * (CGFloat)i, _cursorY, cellWidth - 2.0, height);
        [self fillRect:cell color:(isActive ? self.style.colTabActive : self.style.colTab) radius:3.0];

        if (!_measuring) {
            NSString *label = labels[i];
            CGFloat textWidth = IGTextWidth(label, self.style.fontSize);
            [self.drawList addText:label
                                at:IGVec2Make(CGRectGetMidX(cell) - textWidth / 2.0,
                                              _cursorY + (height - self.style.fontSize) / 2.0 - 0.5)
                          fontSize:self.style.fontSize
                             color:isActive ? self.style.colText : self.style.colTextDisabled];
        }
    }

    _lastItemRect = CGRectMake(x, _cursorY, width, height);
    _cursorY += height + self.style.itemSpacingY;
}

@end
