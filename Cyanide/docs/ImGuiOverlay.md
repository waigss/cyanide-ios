# 全局透明画布 + ImGui 面板（v3：位图传输）

```
canvasView  level 1e6      全屏 1x    网格 / 演示 / 折线      userInteractionEnabled=NO（穿透）
panelView   level 1e6+1    面板 2x    ImGui 面板             隐形 UIKit 控件挂这个窗口
bubbleView  level 1e6+1    圆钮 2x    收起后的恢复按钮
```

三块都是 `CyanidePixelView`：自己建窗口 + `UIImageView`，本进程把一帧渲染成 BGRA
像素，memcpy 进远程 `CGBitmapContext`，再让远程 `CGImage → UIImage → 主线程 setImage:`。

## 一帧的成本

| 步骤 | 远程调用 |
|---|---|
| `remote_write(像素)` | 0（共享页 memcpy，本机内存带宽） |
| `CGBitmapContextCreateImage(ctx)` | 1 |
| `+[UIImage alloc]` | 1 |
| `-[UIImage initWithCGImage:]` | 1 |
| `performSelectorOnMainThread:@selector(setImage:)` | 1 |
| `-[UIImage release]` | 1 |
| `CGImageRelease(上一帧)` | 1 |

**6 次单条 `objc_msgSend` / `dlsym`**，每次只做一次线程劫持，不建 NSInvocation、不 sleep。
剩下的成本是 12MB memcpy（1x 全屏）+ 一次本地光栅化。

对比：

- v1（整屏 PNG + NSInvocation）：一帧 3 条 `r_msg2_main_raw`，每条内部 40~60 次远程
  调用还带 settle，400~600ms/帧。
- v2（CAShapeLayer + CGPath）：一帧 4+N 次调用，快，但只能画描边，写不了文字/填充。

## 关键实现细节

- **远程 `CGBitmapContext` 建在我们自己 malloc 的远程内存上**，所以「推帧」就是往那块
  内存 memcpy，CGImage 只是给它套一层快照（CoW，不额外拷贝 12MB）。
- 两边格式统一 `kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little`，
  本地 `CGContextDrawImage` 出来的字节可以直接用。
- 画布 1x、面板/圆钮 2x：文字必须在 2x 图里才不糊，线条 1x 够用且省一半带宽。
- 沿用 v1 验证过的 `setImage:`（主线程），不再赌 `CATransactionCommit` 跨线程提交。
- 只在内容变化时重画：画布跟 FPS cap 走（演示动画），面板最多 10Hz，静止时零调用。

## 用法

```objc
CyanideImGuiOverlay *o = [CyanideImGuiOverlay sharedOverlay];
[o start];

[o drawPolyline:@[[NSValue valueWithCGPoint:CGPointMake(40,300)],
                  [NSValue valueWithCGPoint:CGPointMake(300,620)]]];
[o drawLineFrom:CGPointMake(0,100) to:CGPointMake(400,900)];
[o drawCircleAt:CGPointMake(200,500) radius:80.0 segments:48];
[o setStrips:@[stripA, stripB]];      // 每帧刷数据用这个
o.lineWidth = 3.0;
o.strokeColor = [UIColor redColor];
o.demoEnabled = YES;                  // 旋转辐条 + 呼吸圆环
o.gridEnabled = YES;
[o clearCanvas];
```

面板里可切：FPS cap（15/30/60）、线宽 1–8、不透明度 5 档、位置 Top/Right/Bottom、
收起面板。第一行显示实测 fps / 每帧调用数 / 单帧毫秒。

## 输入

远程进程跑不了我们的代码，点不了 UIButton。面板上的控件位置摆一组 `alpha = 0.02` 的
隐形 `UISwitch` / `UISegmentedControl`（UIKit 的 hitTest 只忽略 `alpha < 0.01`），
本进程每 66ms 读一次 `isOn` / `selectedSegmentIndex`，一次轮询 7 条单条调用。
不用 `UISlider`：`value` 是 float，返回值在 `s0`，远程调用只保存通用寄存器，读回来是垃圾。

## 已知限制

- 画布是整屏位图：1x 下 1179×2556 = 12MB/帧。60fps 就是 720MB/s 的 memcpy，
  所以默认 cap 是 30。要更省就把 canvas 改成局部区域渲染。
- 线条按 point 画，1x 下在 3x 屏上会略微发虚（2pt 线拉伸成 6px）。
- 面板切位置要设两次 frame（NSInvocation），会顿一下。
- 触摸到画面变化 66~120ms。

## 验证

1. 初始化内核 → 进程详情 → 扳手 → `ImGui 悬浮窗`。
2. 2~5 秒后面板出现，第一行 `N fps · 6 calls · X ms`。`calls` 应是 6（首次 7）。
3. 开 `Demo lines`：旋转辐条 + 呼吸圆环按 cap 跑；`FPS cap` 切 60 看能不能跟上。
4. 面板外滑动/点击，游戏正常响应（穿透）。
5. `Hide panel` → 只剩圆钮，点圆钮恢复。

日志：`[PIXEL] ready win=… buf=… ctx=… 1179x2556 px`、`[IMGUI] running canvas=… panel=…`。
出现 `[PIXEL] setup failed` 说明窗口或位图上下文没建起来。
