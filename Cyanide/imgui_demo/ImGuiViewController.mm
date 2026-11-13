//
//  ImGuiViewController.mm
//  Cyanide
//
//  Dear ImGui v1.93.0 + imgui_impl_metal，跑在 Cyanide App 自己的窗口里。
//
//  为什么先做这一步：ImGui 的渲染、字体图集、输入映射这些如果有问题，在 App 里
//  一眼就能看见、能改；等它在这里稳定了，再把同一份 framebuffer 交给
//  CyanidePixelView 推到 SpringBoard 的全局窗口，两边的问题就不会缠在一起。
//
//  为什么不用 MTKView：本工程的链接阶段没有 MetalKit.framework（只有 Metal 被
//  autolink 进来），所以这里用 CAMetalLayer + CADisplayLink 自己驱动渲染循环 ——
//  MTKView 内部做的也就是这两件事。
//

#import "ImGuiViewController.h"

#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>

#include <math.h>
#include <stdlib.h>

#import "../imgui_core/imgui.h"
#import "../imgui_core/imgui_impl_metal.h"

static const float kPi = 3.14159265358979f;

// CAMetalLayer 支撑的普通 UIView，替代 MTKView。
@interface ImGuiMetalView : UIView
@end

@implementation ImGuiMetalView
+ (Class)layerClass
{
    return [CAMetalLayer class];
}
@end

@interface ImGuiViewController ()
@end

@implementation ImGuiViewController {
    ImGuiMetalView *_metalView;
    id<MTLDevice> _device;
    id<MTLCommandQueue> _commandQueue;
    CADisplayLink *_displayLink;
    UIButton *_closeButton;

    BOOL _started;
    BOOL _showDemo;

    CFTimeInterval _lastFrameTime;
    float _deltaTime;
    float _fps;

    float _lineWidth;
    float _alpha;
    float _phase;

    ImVec2 _points[512];
    int _pointCount;
}

+ (void)presentFrom:(UIViewController *)presenter
{
    if (!presenter) return;
    ImGuiViewController *controller = [[ImGuiViewController alloc] init];
    controller.modalPresentationStyle = UIModalPresentationFullScreen;
    [presenter presentViewController:controller animated:YES completion:nil];
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor blackColor];

    _device = MTLCreateSystemDefaultDevice();
    if (!_device) {
        [self failWithMessage:@"本机没有可用的 Metal 设备"];
        return;
    }

    _metalView = [[ImGuiMetalView alloc] initWithFrame:self.view.bounds];
    _metalView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _metalView.userInteractionEnabled = YES;

    CAMetalLayer *layer = (CAMetalLayer *)_metalView.layer;
    layer.device = _device;
    layer.pixelFormat = MTLPixelFormatBGRA8Unorm;
    layer.framebufferOnly = YES;
    layer.opaque = YES;

    [self.view addSubview:_metalView];
    [self updateDrawableSize];

    _commandQueue = [_device newCommandQueue];

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = nullptr;      // 不往沙盒里写 imgui.ini
    io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGuiStyle &style = ImGui::GetStyle();
    style.WindowRounding = 6.0f;
    style.FrameRounding = 3.0f;
    style.GrabRounding = 3.0f;

    if (!ImGui_ImplMetal_Init(_device)) {
        [self failWithMessage:@"ImGui Metal 后端初始化失败"];
        return;
    }

    _lineWidth = 2.0f;
    _alpha = 0.85f;
    _showDemo = YES;
    _lastFrameTime = CACurrentMediaTime();
    _started = YES;

    [self installCloseButton];

    _displayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(displayLinkFired:)];
    _displayLink.preferredFramesPerSecond = 60;
    [_displayLink addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
}

- (void)viewDidLayoutSubviews
{
    [super viewDidLayoutSubviews];
    [self updateDrawableSize];
}

- (void)updateDrawableSize
{
    if (!_metalView) return;
    CAMetalLayer *layer = (CAMetalLayer *)_metalView.layer;
    CGFloat scale = self.view.window.screen.scale;
    if (scale <= 0.0) scale = [UIScreen mainScreen].scale;
    if (scale <= 0.0) scale = 2.0;

    layer.contentsScale = scale;
    CGSize size = _metalView.bounds.size;
    layer.drawableSize = CGSizeMake(MAX(1.0, size.width * scale), MAX(1.0, size.height * scale));
}

- (void)installCloseButton
{
    _closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_closeButton setImage:[UIImage systemImageNamed:@"xmark.circle.fill"] forState:UIControlStateNormal];
    _closeButton.tintColor = [UIColor whiteColor];
    _closeButton.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.35];
    _closeButton.layer.cornerRadius = 18.0;
    _closeButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_closeButton addTarget:self action:@selector(dismissSelf) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_closeButton];

    [NSLayoutConstraint activateConstraints:@[
        [_closeButton.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:8.0],
        [_closeButton.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12.0],
        [_closeButton.widthAnchor constraintEqualToConstant:36.0],
        [_closeButton.heightAnchor constraintEqualToConstant:36.0],
    ]];
}

- (void)dismissSelf
{
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)failWithMessage:(NSString *)message
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"ImGui 演示启动失败"
                                                                  message:message
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self dismissViewControllerAnimated:YES completion:nil];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - 渲染循环

- (void)displayLinkFired:(CADisplayLink *)link
{
    CFTimeInterval now = CACurrentMediaTime();
    _deltaTime = (float)(now - _lastFrameTime);
    _lastFrameTime = now;
    if (_deltaTime <= 0.0f || _deltaTime > 0.5f) _deltaTime = 1.0f / 60.0f;
    _fps = _fps * 0.9f + (1.0f / _deltaTime) * 0.1f;

    [self renderFrame];
}

- (void)renderFrame
{
    if (!_started) return;

    CAMetalLayer *layer = (CAMetalLayer *)_metalView.layer;
    if (layer.drawableSize.width < 1.0 || layer.drawableSize.height < 1.0) return;

    @autoreleasepool {
        id<CAMetalDrawable> drawable = [layer nextDrawable];
        if (!drawable) return;

        ImGuiIO &io = ImGui::GetIO();
        CGSize points = _metalView.bounds.size;
        if (points.width < 1.0 || points.height < 1.0) return;

        io.DisplaySize = ImVec2((float)points.width, (float)points.height);
        CGFloat scale = layer.drawableSize.width / points.width;
        io.DisplayFramebufferScale = ImVec2((float)scale, (float)scale);
        io.DeltaTime = _deltaTime;

        MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
        pass.colorAttachments[0].texture = drawable.texture;
        pass.colorAttachments[0].loadAction = MTLLoadActionClear;
        pass.colorAttachments[0].storeAction = MTLStoreActionStore;
        pass.colorAttachments[0].clearColor = MTLClearColorMake(0.055, 0.06, 0.075, 1.0);

        id<MTLCommandBuffer> commandBuffer = [_commandQueue commandBuffer];
        if (!commandBuffer) return;

        ImGui_ImplMetal_NewFrame(pass);
        ImGui::NewFrame();
        [self buildUI];
        ImGui::Render();

        id<MTLRenderCommandEncoder> encoder = [commandBuffer renderCommandEncoderWithDescriptor:pass];
        ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, encoder);
        [encoder endEncoding];
        [commandBuffer presentDrawable:drawable];
        [commandBuffer commit];
    }
}

#pragma mark - UI

- (void)buildUI
{
    ImGuiIO &io = ImGui::GetIO();
    _phase += _deltaTime * 1.4f;
    if (_phase > 1000.0f) _phase -= 1000.0f;

    ImGui::SetNextWindowPos(ImVec2(16.0f, 56.0f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(330.0f, 320.0f), ImGuiCond_FirstUseEver);
    ImGui::Begin("Cyanide · ImGui (local)");

    ImGui::Text("fps %.1f   frame %.2f ms", _fps, _deltaTime * 1000.0f);
    ImGui::Text("display %.0f x %.0f   scale %.1f",
                io.DisplaySize.x, io.DisplaySize.y, io.DisplayFramebufferScale.x);
    ImGui::Text("framebuffer %.0f x %.0f",
                io.DisplaySize.x * io.DisplayFramebufferScale.x,
                io.DisplaySize.y * io.DisplayFramebufferScale.y);
    ImGui::Separator();

    ImGui::SliderFloat("Line width", &_lineWidth, 0.5f, 10.0f, "%.1f pt");
    ImGui::SliderFloat("Opacity", &_alpha, 0.05f, 1.0f, "%.2f");

    if (ImGui::Button("add line")) [self addRandomLine];
    ImGui::SameLine();
    if (ImGui::Button("clear")) _pointCount = 0;

    ImGui::Checkbox("show imgui demo", &_showDemo);
    ImGui::Separator();
    ImGui::TextDisabled("touch: tap / drag on screen");

    if (ImGui::Button("close")) [self dismissSelf];

    ImGui::End();

    if (_showDemo) ImGui::ShowDemoWindow(&_showDemo);

    // 背景绘制：证明 ImDrawList 在全屏范围内画得出来
    ImDrawList *background = ImGui::GetBackgroundDrawList();
    const ImVec2 center(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.66f);
    const float radius = (io.DisplaySize.x < io.DisplaySize.y ? io.DisplaySize.x : io.DisplaySize.y) * 0.22f;

    const ImU32 spokeColor = ImGui::ColorConvertFloat4ToU32(ImVec4(0.26f, 0.59f, 0.98f, _alpha));
    for (int i = 0; i < 8; i++) {
        const float angle = _phase + (float)i * (kPi / 4.0f);
        background->AddLine(center,
                            ImVec2(center.x + cosf(angle) * radius, center.y + sinf(angle) * radius),
                            spokeColor,
                            _lineWidth);
    }

    const float ringRadius = 42.0f + 9.0f * sinf(_phase * 2.0f);
    background->AddCircle(center, ringRadius, IM_COL32(255, 255, 255, 110), 48, 1.5f);

    const ImU32 polyColor = IM_COL32(255, 90, 90, (int)(_alpha * 255.0f));
    for (int i = 1; i < _pointCount; i++) {
        background->AddLine(_points[i - 1], _points[i], polyColor, _lineWidth);
    }
}

- (void)addRandomLine
{
    if (_pointCount + 2 > (int)(sizeof(_points) / sizeof(_points[0]))) _pointCount = 0;

    CGSize size = _metalView.bounds.size;
    if (size.width < 1.0 || size.height < 1.0) size = self.view.bounds.size;

    float w = (float)size.width;
    float h = (float)size.height;
    if (w < 1.0f || h < 1.0f) return;

    _points[_pointCount].x = w * 0.5f;
    _points[_pointCount].y = h * 0.66f;
    _pointCount++;
    _points[_pointCount].x = (float)(arc4random_uniform((uint32_t)w));
    _points[_pointCount].y = (float)(arc4random_uniform((uint32_t)h));
    _pointCount++;
}

#pragma mark - 触摸

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self feedTouches:touches down:YES];
}

- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self feedTouches:touches down:YES];
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self feedTouches:touches down:NO];
}

- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self feedTouches:touches down:NO];
}

- (void)feedTouches:(NSSet<UITouch *> *)touches down:(BOOL)down
{
    if (!_started) return;
    UITouch *touch = touches.anyObject;
    if (!touch) return;

    CGPoint point = [touch locationInView:_metalView];
    ImGuiIO &io = ImGui::GetIO();
    io.AddMousePosEvent((float)point.x, (float)point.y);
    io.AddMouseButtonEvent(0, down ? true : false);
}

#pragma mark - 生命周期

- (void)viewDidDisappear:(BOOL)animated
{
    [super viewDidDisappear:animated];
    [self shutdownImGui];
}

- (void)dealloc
{
    [self shutdownImGui];
}

- (void)shutdownImGui
{
    if (!_started) return;
    _started = NO;

    [_displayLink invalidate];
    _displayLink = nil;

    ImGui_ImplMetal_Shutdown();
    ImGui::DestroyContext();
}

@end
