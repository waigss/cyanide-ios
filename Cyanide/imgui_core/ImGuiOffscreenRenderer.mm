//
//  ImGuiOffscreenRenderer.mm
//  Cyanide
//

#import "ImGuiOffscreenRenderer.h"

#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>

#import "imgui.h"
#import "imgui_impl_metal.h"

@implementation ImGuiOffscreenRenderer {
    id<MTLDevice> _device;
    id<MTLCommandQueue> _queue;
    id<MTLTexture> _colorTexture;
    id<MTLBuffer> _readback;

    ImGuiContext *_context;
    ImGuiContext *_savedContext;

    NSUInteger _pixelWidth;
    NSUInteger _pixelHeight;
    CGFloat _scale;

    BOOL _ready;
    BOOL _backendReady;
    bool _demoOpen;
}

- (instancetype)initWithPixelWidth:(NSUInteger)pixelWidth
                       pixelHeight:(NSUInteger)pixelHeight
                             scale:(CGFloat)scale
{
    if (pixelWidth < 16 || pixelHeight < 16) return nil;

    self = [super init];
    if (!self) return nil;

    _pixelWidth = pixelWidth;
    _pixelHeight = pixelHeight;
    _scale = (scale <= 0.0) ? 1.0 : scale;

    _device = MTLCreateSystemDefaultDevice();
    if (!_device) return nil;

    _queue = [_device newCommandQueue];
    if (!_queue) return nil;

    MTLTextureDescriptor *descriptor =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                           width:pixelWidth
                                                          height:pixelHeight
                                                       mipmapped:NO];
    descriptor.usage = MTLTextureUsageRenderTarget;
    descriptor.storageMode = MTLStorageModePrivate;

    _colorTexture = [_device newTextureWithDescriptor:descriptor];
    if (!_colorTexture) return nil;

    _readback = [_device newBufferWithLength:pixelWidth * pixelHeight * 4
                                     options:MTLResourceStorageModeShared];
    if (!_readback) return nil;

    // 自己一份 ImGui 上下文：和 App 内演示页各用各的，互不干扰。
    _savedContext = ImGui::GetCurrentContext();

    IMGUI_CHECKVERSION();
    _context = ImGui::CreateContext();
    if (!_context) return nil;
    ImGui::SetCurrentContext(_context);

    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.DisplaySize = ImVec2((float)(pixelWidth / _scale), (float)(pixelHeight / _scale));
    io.DisplayFramebufferScale = ImVec2((float)_scale, (float)_scale);

    ImGui::StyleColorsDark();
    ImGuiStyle &style = ImGui::GetStyle();
    style.WindowRounding = 6.0f;
    style.FrameRounding = 3.0f;
    style.GrabRounding = 3.0f;

    if (!ImGui_ImplMetal_Init(_device)) {
        ImGui::DestroyContext(_context);
        _context = NULL;
        ImGui::SetCurrentContext(_savedContext);
        return nil;
    }
    _backendReady = YES;

    ImGui::SetCurrentContext(_savedContext);
    _ready = YES;
    return self;
}

- (BOOL)ready { return _ready; }
- (NSUInteger)pixelWidth { return _pixelWidth; }
- (NSUInteger)pixelHeight { return _pixelHeight; }
- (NSUInteger)byteLength { return _pixelWidth * _pixelHeight * 4; }

- (const void *)pixels
{
    return _readback ? _readback.contents : NULL;
}

- (BOOL)renderFrame:(void (^)(void))buildBlock
{
    if (!_ready || !_backendReady || !buildBlock) return NO;

    _savedContext = ImGui::GetCurrentContext();
    ImGui::SetCurrentContext(_context);

    ImGuiIO &io = ImGui::GetIO();
    io.DisplaySize = ImVec2((float)(_pixelWidth / _scale), (float)(_pixelHeight / _scale));
    io.DisplayFramebufferScale = ImVec2((float)_scale, (float)_scale);

    MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
    pass.colorAttachments[0].texture = _colorTexture;
    pass.colorAttachments[0].loadAction = MTLLoadActionClear;
    pass.colorAttachments[0].storeAction = MTLStoreActionStore;
    pass.colorAttachments[0].clearColor = MTLClearColorMake(0.0, 0.0, 0.0, 0.0);

    id<MTLCommandBuffer> commandBuffer = [_queue commandBuffer];
    if (!commandBuffer) {
        ImGui::SetCurrentContext(_savedContext);
        return NO;
    }

    ImGui_ImplMetal_NewFrame(pass);
    ImGui::NewFrame();
    buildBlock();
    ImGui::Render();

    id<MTLRenderCommandEncoder> encoder = [commandBuffer renderCommandEncoderWithDescriptor:pass];
    ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, encoder);
    [encoder endEncoding];

    id<MTLBlitCommandEncoder> blit = [commandBuffer blitCommandEncoder];
    [blit copyFromTexture:_colorTexture
              sourceSlice:0
              sourceLevel:0
             sourceOrigin:MTLOriginMake(0, 0, 0)
               sourceSize:MTLSizeMake(_pixelWidth, _pixelHeight, 1)
                 toBuffer:_readback
        destinationOffset:0
   destinationBytesPerRow:_pixelWidth * 4
 destinationBytesPerImage:_pixelWidth * _pixelHeight * 4];
    [blit endEncoding];

    [commandBuffer commit];
    [commandBuffer waitUntilCompleted];

    ImGui::SetCurrentContext(_savedContext);
    return YES;
}

- (BOOL)renderOverlayFrameWithFPS:(double)fps
                          frameMS:(double)frameMS
                        callCount:(NSUInteger)callCount
                         showDemo:(BOOL)showDemo
{
    return [self renderFrame:^{
        ImGuiIO &io = ImGui::GetIO();

        ImGui::SetNextWindowPos(ImVec2(16.0f, 56.0f), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(340.0f, 0.0f), ImGuiCond_FirstUseEver);
        ImGui::Begin("Cyanide · Global");
        ImGui::Text("fps %.1f    frame %.1f ms", fps, frameMS);
        ImGui::Text("remote calls / frame: %lu", (unsigned long)callCount);
        ImGui::Text("surface %.0f x %.0f", io.DisplaySize.x, io.DisplaySize.y);
        ImGui::Separator();
        ImGui::TextDisabled("this window is rendered by SpringBoard");
        ImGui::End();

        if (showDemo && !_demoOpen) _demoOpen = true;
        if (showDemo) ImGui::ShowDemoWindow(&_demoOpen);
    }];
}

- (void)shutdown
{
    if (!_ready) return;
    _ready = NO;

    _savedContext = ImGui::GetCurrentContext();
    ImGui::SetCurrentContext(_context);

    if (_backendReady) {
        ImGui_ImplMetal_Shutdown();
        _backendReady = NO;
    }
    if (_context) {
        ImGui::DestroyContext(_context);
        _context = NULL;
    }

    ImGui::SetCurrentContext(_savedContext);
}

- (void)dealloc
{
    [self shutdown];
}

@end
