# ImGui 全局悬浮窗（CyanideImGuiOverlay）

在 SpringBoard 里挂三层窗口：一张全屏透明、点击穿透的画布，一块 ImGui 样子的小面板，
以及面板收起后留的一颗圆钮。界面由 Cyanide 进程用 CoreGraphics 画成整帧位图再推过去，
所以看起来是 ImGui，跑起来是「远程贴图 + 隐形控件收输入」。

```
canvasWindow     level 1e6      全屏 · 透明 · userInteractionEnabled = NO   ← 点击穿透
  └─ UIImageView                 Cyanide 渲染好的整帧 PNG
panelWindow      level 1e6+1    只有面板大小 · 上面叠隐形 UIKit 控件         ← 收输入
bubbleWindow     level 1e6+1    面板收起后的小圆钮
```

入口：进程详情页右侧扳手菜单 → `ImGui 悬浮窗`。源码在
`Cyanide/imgui/`（界面）与 `Cyanide/inspector/CyanideImGuiOverlay.{h,m}`（窗口与推帧）。

---

## 1. 为什么是「本地渲染 + 远程贴图」

另一个选择是在 SpringBoard 里建一整棵视图树：UIView 当窗口、UILabel 当文字、UIButton 当按钮。
问题在成本模型：远程每条消息都要抢一次 SpringBoard 线程、走异常端口、等 settle，
默认 `r_settle_us` 是 50ms，一条 `r_msg2_main`（NSInvocation 那条路）内部还有十来次 settle。
面板里十几个控件，一次全量刷新就是几十条消息 —— 秒级。

改成整帧位图以后，帧成本和图元数量无关：

| 步骤 | 远程消息数 |
|---|---|
| `remote_write` 把 PNG 写进 SpringBoard 可读的缓冲区 | 0（共享页 memcpy） |
| `+[NSData dataWithBytes:length:]` | 1 |
| `+[UIImage imageWithData:scale:]` | 1 |
| `-[UIImageView setImage:]` | 1 |

一帧 3 条消息，8ms settle 下大约 150~300ms 一帧（3~6 fps），够看。

代价是**没法命中测试**：图是死的，触摸打不到图上的按钮。

## 2. 输入怎么回来

远程进程里跑不了我们的代码，所以点不了 UIButton。做法是把一组**隐形控件**摆在图上控件
的位置，用 `alpha = 0.02` 让它们可点但几乎不可见（UIKit 的 hitTest 只忽略 `alpha < 0.01`，
0.02 仍然参与命中测试）。本进程每 160ms 读一次它们的 state：

| 图上画的 | 远程真控件 | 读法 |
|---|---|---|
| 复选框 | `UISwitch` | `isOn` → BOOL |
| 分段滑条 | `UISegmentedControl` | `selectedSegmentIndex` → NSInteger |
| 位置 Tab | `UISegmentedControl` | `selectedSegmentIndex` → NSInteger |
| 收起按钮 | `UISwitch`（圆钮里那颗） | `isOn` |

**为什么不用 UISlider**：`-[UISlider value]` 返回 `float`，而 `do_remote_call_stable` 只保存
通用寄存器（x0–x28），AArch64 上浮点返回值在 `s0`，和 `x0` 不是同一个寄存器文件 —— 读回来是垃圾。
`NSInvocation` 那条路（`r_msg2_main_raw`）能正确取回浮点，但每条要几百毫秒，拖滑条会粘手。
所以数值型控件用分段选择，档位是整数：线宽 1–8 八档，不透明度五档（40/95/150/205/255）。

三个布尔/整数读都是零参 `objc_msgSend`（`r_msg`），一条消息一个值，一次轮询六条，很快。

## 3. 点击穿透

`canvasWindow.userInteractionEnabled = NO`，整棵子树都不参与命中测试，触摸直接落到下层的
游戏/App 上。`panelWindow` 只有面板那么大，面板以外的区域它一点都接不住。
把面板收起（`Hide panel`）时还会把 `panelWindow.userInteractionEnabled` 置 0，
只留圆钮那颗 38×38 的窗口 —— 这时屏幕上除了那个圆点，全部穿透。

## 4. 画布 API

坐标是屏幕 point，原点左上、y 向下，和 UIKit 一致。线程安全，随便哪个队列调都行。

```objc
CyanideImGuiOverlay *overlay = [CyanideImGuiOverlay sharedOverlay];
[overlay start];                                   // 异步挂载，几秒

[overlay clearCanvas];
[overlay drawLineFrom:CGPointMake(40, 300)
                   to:CGPointMake(300, 620)
                color:[UIColor colorWithRed:0.26 green:0.59 blue:0.98 alpha:0.9]
                width:2.0];
[overlay drawRect:CGRectMake(60, 400, 200, 120) color:[UIColor redColor] width:1.0];
[overlay drawCircleAt:CGPointMake(180, 380) radius:60.0 color:[UIColor yellowColor] width:1.5];
[overlay drawText:@"hello" at:CGPointMake(80, 340) size:14.0 color:[UIColor whiteColor]];
```

图元存在本地数组里，每次推帧重画；上限 4096 条，超了从头开始丢。
`demoEnabled = YES` 会跑一个八芒星 + 脉冲圆环的动画（不用外部喂数据也能确认链路通），
`gridEnabled = YES` 叠一层 60pt 网格和屏幕中心十字。

画布尺寸固定为 `UIScreen.mainScreen.bounds.size`，图像按 `scale = min(screenScale, 2.0)` 渲染。

## 5. 性能旋钮

| 常量 | 值 | 作用 |
|---|---|---|
| `kIGSettleMicroseconds` | 8000 | 批量远程调用期间的 settle（默认 50000）。调大更稳，调小更快 |
| `kIGTickInterval` | 0.16s | 轮询间隔 |
| `kIGMinPushInterval` | 0.15s | 两帧之间最小间隔，防止动画把队列塞满 |
| `kIGRenderScale` | 2.0 | 位图倍率；1.0 可省一半带宽和内存 |
| `kIGRemoteBufferBytes` | 4MB | 远程缓冲区；PNG 超过它就推不出去 |
| `kIGMaxPushFailures` | 4 | 连续推帧失败几次后自毁并写日志 |

`r_settle_us` 是进程级全局量，进批量操作前改成 8ms、出来后恢复原值，不会影响别的功能。

## 6. 已知限制

- **不是真 ImGui**：没有 ImGui 的 docking / 拖拽 / 输入框，只复刻了窗口、标题栏、边框、
  分隔线、复选框、滑条、按钮、Tab 这几种外观和逐行布局的写法。
- **一帧一张 PNG**：1080p 下 PNG 编码在几十毫秒量级，`renderScale` 调低或减少动画频率
  比优化远程调用更有效。
- **触摸有延迟**：拨开关到画面变化要等下一次轮询 + 下一帧，实测 0.2~0.5s。
- **面板不能拖动**：位置只有 Top / Right / Bottom 三个预设（Tab 切换）。
- **推帧失败会自毁**：连续 4 次失败会拆窗口并置状态为停止，日志里有 `[IMGUI] push failed`。

## 7. 验证

装好 IPA 后：

1. 进 Cyanide → 进程页 → 初始化内核 → 进任意进程详情 → 扳手菜单 → `ImGui 悬浮窗`。
2. 等 2~5 秒，左上角出现深色面板，标题 `Cyanide · ImGui`，第一行 `fps / prims`。
3. 回桌面或打开别的 App，面板仍在（`DSKeepAlive` 会保活 Cyanide）。
4. 拨 `Demo lines`，屏幕上出现旋转的线；拨 `Grid + crosshair`，出现网格。
5. 在面板以外的地方滑动/点击，游戏正常响应 —— 穿透成立。
6. 点 `Hide panel`，面板消失、只剩圆钮；点圆钮恢复。

日志（`[IMGUI]` 前缀）：

```
[IMGUI] start: screen=1179x2556 scale=2.0
[IMGUI] SpringBoard session ok pid=...
[IMGUI] windows: canvas=0x... panel=0x... bubble=0x... image=0x...
[IMGUI] remote buffer 0x... (4194304 bytes)
[IMGUI] running
```

出现 `image push not verified` 说明推图这条路没通，面板里会落一个 UILabel 兜底；
`SpringBoard 会话失败` 说明远程调用没建立，先确认内核已初始化。
