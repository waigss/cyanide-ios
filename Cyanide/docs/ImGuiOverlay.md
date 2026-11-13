# 全局透明画布 + ImGui 面板（v2：矢量画线）

在 SpringBoard 里挂三层窗口：

```
canvasWindow   level 1e6      全屏 · 透明 · userInteractionEnabled = NO   ← 点击穿透
  └─ CAShapeLayer(s)          画线：远程建 CGPath，渲染服务器合成
panelWindow    level 1e6+1    只有面板大小 · 叠隐形 UIKit 控件收输入
bubbleWindow   level 1e6+1    面板收起后的圆钮（一张一次性渲染的小图）
```

入口：进程详情页右侧扳手 → `ImGui 悬浮窗`。源码：
`Cyanide/inspector/CyanideScreenCanvas.{h,m}`（画布）、
`Cyanide/inspector/CyanideImGuiOverlay.{h,m}`（面板与输入）、
`Cyanide/imgui/`（ImGui 外观）。

---

## 1. 为什么 v1 只有 2~3 fps

v1 每帧把整屏画成 PNG 再推给 SpringBoard 的 `UIImageView`。一帧的远程调用是：

```
+[NSData dataWithBytes:length:]      ← 走 r_msg2_main_raw
+[UIImage imageWithData:scale:]      ← 走 r_msg2_main_raw
-[UIImageView setImage:]             ← 走 r_msg2_main_raw
```

`r_msg2_main_raw` 为了支持任意签名/浮点参数，内部要建 `NSInvocation`、
查 `methodSignatureForSelector:`、逐个 `setArgument:atIndex:`、`retainArguments`、
再 `performSelectorOnMainThread:` —— **一条这样的消息内部就是 40~60 次远程调用**，
而且每次 `r_msg2` 前后还带 `r_settle()`（默认 50ms 的 usleep）。
三条消息叠起来 = 一帧几百毫秒，屏幕越大 PNG 编码越久。

## 2. v2 的做法

画线不再传像素。点数组写进共享页（`remote_write` 是 memcpy），让**远程进程的
CoreGraphics** 建一条 `CGPath` 设给 `CAShapeLayer`，由渲染服务器合成：

```
remote_write(点数组)                 0 次远程调用（共享页 memcpy）
CGPathCreateMutable                  1
CGPathAddLines / CGPathAddPath       N（每条折线 1~3 次，见下）
-[CAShapeLayer setPath:]             1
CGPathRelease(上一帧的 path)          1
CATransactionCommit                  1
```

一帧 4 + N 次**单条** `objc_msgSend` / `dlsym` 调用，每次只做一次线程劫持，
不建 NSInvocation，不 sleep。实测量级：单条折线 5 次调用 ≈ 1~3ms。

几个必须注意的点：

- **`CGPathAddLines` 不能连续调**。它在非空 path 上会接在当前点后面画，两条折线
  会被串成一条。所以多折线时每条单独 `CGPathCreateMutable` + `CGPathAddLines`，
  再 `CGPathAddPath` 合并（子路径保持独立），用完 `CGPathRelease`。
- **改 layer.path 是在被劫持的线程上**。CALayer 属性本身线程安全，但改动落在
  线程本地事务里，必须 `CATransactionCommit()` 才会送到渲染服务器 —— 这是 0 参
  C 函数，一次调用。
- **面板推图只剩 3 条消息**（都走 `r_msg`，单次调用）：
  `dataWithBytes:length:` → `imageWithData:` →
  `performSelectorOnMainThread:withObject:waitUntilDone:`（`setImage:`，一条消息
  把调用甩到主线程，`waitUntilDone:YES`）。而且只渲染面板本身（252×H），
  只在控件变化时推。

## 3. 输入怎么回来

远程进程里跑不了我们的代码，点不了 UIButton。做法是把一组**隐形控件**摆在图上控件
的位置，`alpha = 0.02`（UIKit 的 hitTest 只忽略 `alpha < 0.01`），本进程每 66ms
读一次 state，每次轮询 7 次单条调用：

| 图上画的 | 远程真控件 | 读法 |
|---|---|---|
| 复选框 | `UISwitch` | `isOn` → BOOL |
| 分段滑条 / Tab | `UISegmentedControl` | `selectedSegmentIndex` → NSInteger |

不用 `UISlider`：`-[UISlider value]` 返回 `float` 在 `s0`，而远程调用只保存
通用寄存器，AArch64 上浮点和通用寄存器不是同一组 —— 读回来是垃圾。
`NSInvocation` 那条路能取回浮点但太贵，所以数值控件一律整数化（线宽 1–8、
不透明度 5 档、帧率 15/30/60）。

## 4. 用法

```objc
CyanideImGuiOverlay *overlay = [CyanideImGuiOverlay sharedOverlay];
[overlay start];                       // 异步挂载，几秒

// 一条折线
[overlay drawPolyline:@[
    [NSValue valueWithCGPoint:CGPointMake(40, 300)],
    [NSValue valueWithCGPoint:CGPointMake(300, 620)],
]];

// 一条直线 / 一个圆（折线近似）
[overlay drawLineFrom:CGPointMake(0, 100) to:CGPointMake(400, 900)];
[overlay drawCircleAt:CGPointMake(200, 500) radius:80.0 segments:48];

// 一次替换全部（每帧刷数据用这个）
[overlay setStrips:@[stripA, stripB]];

overlay.lineWidth = 3.0;
overlay.strokeColor = [UIColor redColor];
overlay.demoEnabled = YES;             // 旋转辐条 + 呼吸圆环，用来量帧率
overlay.gridEnabled = YES;             // 静态网格（一次性建好，开关只发 setHidden:）
[overlay clearCanvas];
```

坐标是屏幕 point，原点左上，y 向下。画布整层 `userInteractionEnabled = NO`，
触摸直接落到下面的游戏；面板收起后除那颗 38×38 圆钮外全部穿透。

单帧点上限 16384（缓冲区 256KB，超了截断）。

## 5. 性能旋钮（面板里都能改）

| 项 | 默认 | 说明 |
|---|---|---|
| FPS cap | 60 | 画布刷新上限：15 / 30 / 60 |
| Line width | 2pt | 1–8 档，只在变化时下发 |
| Opacity | 255 | 5 档，折算成 strokeColor 的 alpha |
| 轮询 | 15Hz | 读 7 个隐形控件 |
| 面板推图 | ≤10Hz | 只有控件变化才推 |

内部常量在 `CyanideImGuiOverlay.m` 顶部：`kIGTickInterval`、`kIGPollInterval`、
`kIGPanelPushInterval`、`kIGPanelBufferBytes`。

## 6. 已知限制

- 画布是**矢量描边**：没有文字、没有填充色块、没有位图贴图。文字仍然只能画在
  面板那张图里。
- 单条折线一次 `CGPathAddLines`；折线很多时每帧多 N 次调用（8 条 ≈ 30 次调用，
  仍然比 v1 快两个数量级，但会掉到 30fps 左右）。
- 面板位置只有 Top / Right / Bottom 三档（切档要设两次 frame，会卡一下）。
- 触摸到画面变化 66~120ms（轮询 + 推帧）。
- 推帧连续失败 5 次只报警不再推，不会自毁。

## 7. 验证

1. 进程页初始化内核 → 进任意进程详情 → 扳手 → `ImGui 悬浮窗`。
2. 2~5 秒后左上角出现面板，第一行是 `canvas N fps · M calls`（M 应是个位数），
   第二行 `canvas X ms  panel Y ms`。
3. 开 `Demo lines`：中心出现旋转辐条和呼吸圆环。把 `FPS cap` 切 60，帧率应跟到
   接近 60（受 SpringBoard 主线程合成节流），`canvas ms` 在 1~3ms 量级。
4. 开 `Grid`：整屏 64pt 网格。
5. 面板外滑动/点击，游戏正常响应 —— 穿透成立。
6. `Hide panel`：面板消失只剩圆钮，点圆钮恢复。

日志（`[IMGUI]` / `[CANVAS]`）：

```
[IMGUI] session ok pid=...
[IMGUI] panel=0x... image=0x... bubble=0x... scene=0x...
[CANVAS] attached window=0x... line=0x... grid=0x...
[IMGUI] running
```

`[CANVAS] attach failed` = 窗口或图层没建起来；
`canvas 0 fps` 而 `calls` 不涨 = `setStrips:` 没被调用（`_canvasDirty` 没置位）。
