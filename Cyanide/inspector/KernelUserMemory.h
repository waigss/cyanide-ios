//
//  KernelUserMemory.h
//  Cyanide
//
//  不附加目标进程、不创建线程，直接从内核页表读目标进程的用户态内存。
//
//  原理：proc → task → vm_map → pmap → 根页表(tte)
//        用 tte - ttep 得到页表窗口偏移，然后按 16KB 页、3 级页表遍历：
//        L0: VA[47:36] → L1: VA[35:25] → L2: VA[24:14] → 页内 VA[13:0]
//        页表项里的物理地址只有 bit[47:14]，高位是属性位。
//
//  已验证：对自身一个已知字符串做翻译 + 逐字节比对，结果完全一致。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// 为某个进程准备页表上下文。proc 是内核里 struct proc 的地址。
BOOL kum_prepare(uint64_t proc);

// 目标进程的地址空间范围。
uint64_t kum_map_min(void);
uint64_t kum_map_max(void);

// 从目标进程的用户态地址读内存。地址未映射时返回 NO（不会崩溃）。
BOOL kum_read(uint64_t va, void *dst, size_t len);

// 不依赖 dyld 表，直接从地址空间最低端扫出主程序基址（校验 Mach-O 头）。
// 只要主程序地址时用这个最省事，不需要附加。
BOOL kum_main_executable_base(uint64_t * _Nullable outBase);

// 读目标进程的 dyld 镜像列表：@[ @{name, path, base} ]。
// 失败时返回 nil 并通过 errorOut 给出中文原因。
NSArray<NSDictionary<NSString *, id> *> * _Nullable kum_read_dyld_images(NSString *_Nullable *_Nullable errorOut);

NS_ASSUME_NONNULL_END
