# py/ -- WinNotify.sys → Python → .exe

Python equivalent of `src/PhysicalMemory.pas` + `src/KernelBridge.pas`,
rebuilt against the **real** driver ABI (`0x22200C / 0x222040 / 0x222044` for
kernel R/W-machinery and `0x222000 / 0x222004` for per-process CR3 R/W).
See section 3.1: the lengths below are validated by the driver, the Pascal
bridge sent the wrong ones (ERROR_BAD_LENGTH / WinError 24).

```
py/
  winnotify.py            内核层: 驱动加载 + IOCTL + EPROCESS 遍历 + 进程读写
  cli.py                  CLI  (.exe 入口)
  winnotify.json.example  偏移/IOCTL 覆盖配置 (可选, 放在 exe 旁边)
  README.md               本文
  build.ps1               PyInstaller 打包脚本
  requirements-build.txt  打包依赖
```

> ⚠️ **会蓝屏的风险点(已处理,请先读这一节)**
> 这个驱动对传入的地址**不做任何校验**,错一个地址 = 立刻 `BUGCHECK`。
> 旧版本会「挨个试偏移」并把结果直接交给驱动,这就是上次蓝屏的来源。
> 现在:
> * 只向驱动发送**规范内核地址**(`>= 0xFFFF800000000000`),用户态/非规范地址一律在本地拦下;
> * 进程读写只走 `0x222000/0x222004`(驱动自己翻页表、失败返回状态码,**不会**蓝屏);
> * 内核读到的每个候选都先做**结构校验**(Flink/Blink 是内核指针、DTB 像 CR3、PID 合理),不合法就直接放弃;
> * 猜测默认**关闭**:`ps_initial_system_offsets` 只用第一个,`probe_ps_offsets` 默认 false;
> * `selftest` 不再猜任何内核地址(只用 image base / PEB / 新分配内存,全在用户态取得);
> * `read`/`write` 遇到 `0x0`、`<0x10000`、内核地址、跨出用户空间的长度,直接拒绝。
>
> 第一次在 Win10 21H2(19044) 上建议按下面顺序跑:
> `selftest` → `memory-test` → `info` → 再动游戏。
> 调 `info` 时用 `--max-offsets 1` 只测一个候选,最保险。

## 1. 打包成 exe

Windows 上(管理员 PowerShell):

```powershell
cd py
powershell -ExecutionPolicy Bypass -File .\build.ps1
# -> py\dist\winnotify-cli.exe   (单文件, 控制台程序)
```

也可以在任意机器上直接跑源码,不用打包:

```powershell
python cli.py selftest
python cli.py PlantsVsZombies.exe 0x0019A5B8 999
```

需要 Python 3.9+ 64-bit;脚本会自动 `pip install pyinstaller`。其它写法:

```powershell
python -m PyInstaller --onefile --console --name winnotify-cli cli.py
```

## 2. 使用(就是你说的测试流程)

把 `WinNotify.sys` 放到 exe 同目录(或 `C:\Windows\System32\drivers\`),
以**管理员**运行:

```bat
:: 进程 + 阳光地址 + 新值   ---- 最简形式(等价于 write 子命令)
winnotify-cli.exe PlantsVsZombies.exe 0x0019A5B8 999

:: 显式 write
winnotify-cli.exe write PlantsVsZombies.exe 0x0019A5B8 999

:: 先读一下确认地址对不对
winnotify-cli.exe read PlantsVsZombies.exe 0x0019A5B8 -n 16

:: 阳光会被游戏持续扣/加, 需要锁定时
winnotify-cli.exe freeze PlantsVsZombies.exe 0x0019A5B8 999 -i 0.1

:: 自检: 驱动加载 -> ntoskrnl base -> EPROCESS 遍历 -> CR3 页表读写
winnotify-cli.exe selftest

:: 权限诊断(不发任何 IOCTL,纯用户态)
winnotify-cli.exe privcheck

:: 安全的自读自写测试(只动自己进程的 4 KB 新内存,不会蓝屏)
winnotify-cli.exe memory-test

:: 排障: 系统版本 + PsInitialSystemProcess 候选偏移命中情况(只读)
winnotify-cli.exe info --max-offsets 1
```

* `<proc>` 可以写 PID(`1234` / `0x4D2`)或进程名(`PlantsVsZombies.exe`)。
* `<addr>` 是目标进程里的**虚拟地址**(和 CE 里看到的地址一样),`0x` 或十进制均可。
* 值类型默认 `int32`,其它:`-t uint|int64|float|bytes|string`。
* `--unload` 结束后停止并删除驱动服务;默认保留(下次启动直接复用)。
* `--driver X:\path\WinNotify.sys` 指定驱动路径。

Python 里直接用:

```python
from winnotify import WinNotify, resolve_pid

dev = WinNotify()                       # 自动找 exe 旁边的 WinNotify.sys
dev.start()
pid = resolve_pid("PlantsVsZombies.exe")
print(dev.read_int32(pid, 0x0019A5B8))
dev.write_int32(pid, 0x0019A5B8, 999)   # 阳光
dev.write_float(pid, 0x0019A5B8, 999.0) # 或浮点
dev.stop()
```

## 3. 驱动/系统不匹配时:winnotify.json

驱动版本或 Windows 版本不同,偏移/IOCTL 就不一样。把 `winnotify.json.example`
复制成 `winnotify.json` 放到 exe 旁边改即可(字符串 `"0x448"` 会被自动转成整数):

| 字段 | 含义 | 默认(真实驱动 ABI) |
|---|---|---|
| `ioctl_info/read/write` | 内核读机制 IOCTL | `0x22200C/40/44` |
| `ioctl_vread/vwrite` | 按 CR3 直读直写 | `0x222000/0x222004` |
| `info_in_size/read_in_size/write_in_size/vioctl_size` | 每个 IOCTL 要求的**精确**输入长度 | `0x18/0x38/0x18/0x28` |
| `use_direct_vioctl` | 用 0x222000/04 直读直写;false 则回退 0x222040/44 | `true` |
| `autodetect` | 长度/布局不符时自动试探并记住 | `true` |
| `eprocess_probe_shifts` | pid/links 偏移位移候选(Win11 24H2 为 0x10) | `[0x10, 0]` |
| `device_path` | 设备符号链接 | `\\.\WinNotify` |
| `service_name` | 服务名 | `WinNotify` |
| `eprocess_links/pid/dtb` | EPROCESS 偏移 | `0x448/0x440/0x28` |
| `ps_initial_system_offsets` | PsInitialSystemProcess 相对 ntoskrnl 的偏移候选 | 5 个候选 |
| `read_bias/read_result_offset` | READ IOCTL 的“地址-0x10”怪癖 | `0x10/0x20` |
| `info_result_offset` | INFO IOCTL 返回内核基址的位置 | `0x10` |
| `keep_service` | 退出时是否保留驱动服务 | `true` |
| `preferred_ps_offset` | 你机子的 `PsInitialSystemProcess` 偏移(优先使用) | `0xCFC420` |
| `probe_ps_offsets` | 是否依次尝试其它候选(会多解引用,默认关) | `false` |
| `probe_eprocess_shifts` | 是否尝试 pid/links `+0x10`(Win11 24H2) | `false` |
| `vioctl_chunk` | 单次虚拟读写字节数(越小越温和) | `0x1000` |
| `info_name_is_pointer` | `0x22200C` 的 `+0x00` 放用户态指针(**绝对不要关**) | `true` |
| `vet_ioctl_packets` | 发送前校验每个 IOCTL 里的指针 | `true` |
| `ensure_debug_privilege` | 调 `0x22200C` 前确保 SeDebugPrivilege 已启用 | `true` |
| `fallback_kernel_base` | 驱动返回 0 时用 `NtQuerySystemInformation` 取内核基址 | `true` |
| `force_unload` | 允许 `--unload` 停止刚启动的驱动(可能蓝屏,默认拒绝) | `false` |

`selftest` 会逐段报告哪一步失败,对应改哪个字段。

> `selftest` 默认拿**自己这个进程**做读写验证(不需要游戏在跑);
> 想测别的进程用 `winnotify-cli.exe selftest --pid 1234`
> 或 `... selftest --pid PlantsVsZombies.exe`。

## 3.1 驱动 ABI(已验证)

第一次跑 `selftest` 报 `DeviceIoControl(0x22200C) WinError 24`(= ERROR_BAD_LENGTH),
原因是 Pascal 版传的输入长度不对 —— **该驱动对每个 IOCTL 校验精确输入长度**。
按公开逆向结论(signeddrv.sys / WinNotify.sys):

| IOCTL | 输入长度 | 结构 | 输出 |
|---|---|---|---|
| `0x22200C` 取模块基址 | `0x18` | `[+0] 指向 "ntoskrnl.exe" 的**用户指针**(不是字节!)` | `+0x10 = base`(共 0x20) |
| `0x222040` 内核读 | `0x38` | `[+0] base`, `[+8] offset` | `+0x10..0x30` 5 个 QWORD,仅当 `*(base+0x10)!=0` 才回写 |
| `0x222044` 内核写 | `0x18` | `[+0] src`, `[+8] size`, `[+10] dst` | `memmove(dst, src, size)` |
| `0x222000` 虚拟读 | `0x28` | `[+0] flags(0)`, `[+8] va`, `[+10] buf`, `[+18] size`, `[+20] CR3` | 数据写进 `buf` |
| `0x222004` 虚拟写 | `0x28` | 同上 | 从 `buf` 写进目标进程 |

因此:

* `0x222000/0x222004` 成为**主路径**:把目标进程 CR3 交给驱动翻页表,
  不再自己逐页读物理内存,也不依赖 `0x222050/0x222054`;
* `0x222040/0x222044` 用于 EPROCESS 遍历,并作为回退路径(`"use_direct_vioctl": false`);
* 所有长度/偏移都可覆盖,且默认**自动探测**:INFO 先试 `0x18` 再试 `0x28`,
  READ 试 `0x38/0x40` 与 bias `0x10/0`,虚拟读写试 `0x28` 与
  `[cr3][va][size][buf]` 旧布局;命中后打印 `[i] ... auto-detected` 并记住。

## 3.2 修改记录

* **v6 (2026-11-23)**: **修复 `0x22200C` 返回 0**。
  驱动内部走 `ZwQuerySystemInformation(SystemModuleInformation)`(信息类 0xb),
  这个类只有在调用方令牌的 **SeDebugPrivilege 处于启用状态**时才会返回模块列表,
  否则列表为空 -> 驱动返回 0。管理员默认"持有但禁用"该权限,所以必须主动启用。
  现在启动时会自动 `AdjustTokenPrivileges` 打开 SeDebugPrivilege;
  若仍然拿不到,则用用户态 `NtQuerySystemInformation` 自己解析
  `_RTL_PROCESS_MODULE_INFORMATION`(0x130 字节,`ImageBase` 在 +0x00,
  `FullDllName` 在 +0x28)作为回退。另新增 `privcheck`(不发任何 IOCTL)。
* **v5 (2026-11-23)**: **修复 `selftest` 蓝屏的真正原因**。
  `0x22200C` 的 `+0x00` 不是一个字符串,而是**指向模块名字符串的用户态指针**;
  旧代码把 `"ntoskrnl.exe"` 的字节写在 `+0x00`,驱动于是把
  `0x6C726E6B736F746E`(ASCII)当地址解引用 -> 立即 BSOD。
  之前一直没炸是因为长度算错(24),驱动在解引用**之前**就返回了。
  现在 `+0x00` 永远是 `ctypes.create_string_buffer` 的地址;
  另外新增**发送前包校验**(`vet_ioctl_packets`),任何 IOCTL 里的指针
  只要不是"我们自己的用户指针"或"规范内核地址"就在本地被拦下。
* **v4 (2026-11-23)**: **修复蓝屏**。
  * 所有发往驱动的内核地址强制走规范化/内核区间检查(`_gate_kernel_addr`);
  * `read_memory`/`write_memory` 增加用户态地址守卫(0 页、`<0x10000`、内核地址、跨界);
  * EPROCESS 候选先结构校验(`_looks_like_eprocess`)再使用;
  * 偏移探测默认关闭(`probe_ps_offsets` / `probe_eprocess_shifts`),只认配置里第一个;
    Win10 21H2(19044) 的 `0xCFC420` 已放到默认第一位;
  * `use_direct_vioctl` 为 true 时非法页由驱动返回状态码,不再由用户态解析页表;
  * `selftest` 改为完全不猜内核地址,新增 `memory-test`、`info --max-offsets`;
  * 新增回归:任何不安全地址在到达驱动前就被拒绝(见 README 第 5 节)。
* **v3 (2026-11-23)**: 按真实驱动 ABI 重写 IOCTL 层(见 3.1),修复 `WinError 24`;
  新增 `0x222000/0x222004` 直读直写;长度/布局自动探测;EPROCESS 支持
  Win11 24H2+ 的 `+0x10` 位移;新增 `winnotify-cli.exe info`。
* **v2 (2026-11-23)**: 修复首次打包后 `selftest` 直接崩在 import 的问题。
  `LookupPrivilegeValueW` / `AdjustTokenPrivileges` / `OpenProcessToken` /
  `OpenSCManagerW` 等其实在 **advapi32.dll**,之前错绑到 kernel32 上,
  打包成 exe 后 `function 'LookupPrivilegeValueW' not found`。
  现在按 DLL 分组声明原型、逐个 `try/except` 绑定,缺函数不会中断 import;
  运行时任何异常都打印成一行中文友好的 `[ERROR]`,不再抛 traceback。
* 输出全部改为 ASCII,避免 cp936 控制台乱码/编码异常。

## 4. 安全模型:为什么不会再蓝屏

| 场景 | 旧行为 | 现在 |
|---|---|---|
| `0x222040` 收到用户态/非规范地址 | 驱动直接解引用 -> BSOD | 本地拒绝,IOCTL 根本不发 |
| `PsInitialSystemProcess` 偏移不对 | 把垃圾当指针继续读 | 结构校验不过 -> 停下,不崩 |
| 读进程里未映射的页 | 用户态自己猜物理地址再读 | `0x222000` 由驱动返回状态码 |
| `read`/`write` 传 `0x0` / 内核地址 | 直接下发 | 本地拒绝 |
| `0x22200C` 的 `+0x00` 写成字符串字节 | 驱动把 ASCII 当地址 -> BSOD | 自动放用户态指针,且发送前校验 |
| `SeDebugPrivilege` 未启用 | `0x22200C` 静默返回 0 | 自动启用;失败则用 `NtQuerySystemInformation` 回退 |
| 任何 IOCTL 里出现非法指针 | 驱动直接解引用 | `_vet_ioctl_packet` 本地拦截 |
| 猜 EPROCESS `+0x10` 位移 | 自动尝试 | 默认关闭,`probe_eprocess_shifts` 才开 |

```
PS> winnotify-cli.exe selftest
[1/5] driver       : E:\...\signeddrv.sys
[2/5] ntoskrnl      : 0xFFFFF800...   (KASLR defeated, no address guessed)
[3/5] EPROCESS/CR3  : 0x1AD000   (pid 1234, this process)
[4/5] page-table R/W: read b'MZ' at 0x7FF6... (image base (MZ)) -- OK
[5/5] write test   : wrote+verified b'WINNOTIFY-SELFTEST' at 0x...
[OK] all safe checks passed -- driver, kernel base, EPROCESS walk and page-table R/W work
```

仍然有残余风险的只有一处:`info --max-offsets N`(N>1)会为每个候选解引用一次
去读 PID。默认只测 1 个;把已知偏移写进 `preferred_ps_offset` 后可以完全不猜。

### Win10 21H2(19044) 的偏移

`19041/19042/19043/19044/19045` 是同一套 EPROCESS 布局:

| 字段 | 偏移 |
|---|---|
| `DirectoryTableBase` | `0x28` |
| `UniqueProcessId` | `0x440` |
| `ActiveProcessLinks` | `0x448` |
| `PsInitialSystemProcess`(相对 ntoskrnl) | `0xCFC420` |

如果 `selftest` 停在 `[3/5]`,把 `winnotify.json` 里
`"preferred_ps_offset"` 写成你机子上 `PsInitialSystemProcess` 的真实偏移
(用 `info --max-offsets 1` 或 Windbg 的 `x nt!PsInitialSystemProcess` 确认)。

## 5. 说明 / 边界

* 这是 `src/PhysicalMemory.pas` 的**纯 Python 移植**,不是新驱动:驱动验证、加载方式
  仍由 WinNotify.sys 自己决定;工具只负责 `CreateService + StartService + DeviceIoControl`。
* 写内存走“驱动按 CR3 翻页表 → 读整页 → 改 → 写回”,所以不需要 `OpenProcess` 句柄,
  也不受目标进程句柄保护影响;但**不要**拿它改与游戏完整性校验相关的代码段。
* 只在本机、你自己有权限的进程上用。测试建议先在 `selftest` 通过后再动游戏。
