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
:: 若当前不是管理员,工具会自己弹 UAC 以管理员重启;不想重启就用 --no-elevate

:: 安全的自读自写测试(只动自己进程的 4 KB 新内存,不会蓝屏)
winnotify-cli.exe memory-test

:: 排障: 系统版本 + 驱动的地址来源 + EPROCESS 链(只读)
winnotify-cli.exe info --max-offsets 8
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
| `kernel_base_via_system_info` | **优先**用用户态模块列表取内核基址(不需要令牌特权) | `true` |
| `fallback_kernel_base` | 驱动返回 0 时再试一次用户态模块列表 | `true` |
| `force_unload` | 允许 `--unload` 停止刚启动的驱动(可能蓝屏,默认拒绝) | `false` |

`selftest` 会逐段报告哪一步失败,对应改哪个字段。

> `selftest` 默认拿**自己这个进程**做读写验证(不需要游戏在跑);
> 想测别的进程用 `winnotify-cli.exe selftest --pid 1234`
> 或 `... selftest --pid PlantsVsZombies.exe`。

## 3.1 驱动 ABI(逐条反汇编核对过)

之前几版都是"照着别人的逆向文章猜结构",所以一直对不上。这次把
`Haider303/winnotify-exp` 里的 **signed.sys 本体**反汇编,逐条指令读出
真实的 dispatcher,结论如下(每一项都能在二进制里指到具体指令):

| IOCTL | 输入长度 | 结构 | 输出 |
|---|---|---|---|
| `0x22200C` 取模块基址 | `0x18` | `[+0] 指向 "ntoskrnl.exe" 的**用户指针**(不是字节!)` | `+0x10 = base` |
| `0x222040` 内核读 | `0x38` | `[+0] base`, `[+8] offset` | `+0x10..0x30` 共 5 个 QWORD,仅当 `*(base+offset+0x10)!=0` 才回写 |
| `0x222044` 内核写 | `0x18` | `[+0] src`, `[+8] size`, `[+0x10] dst` | `memmove(dst, src, size)` |
| `0x222000` 虚拟读 | `0x28` | `[+0] **PID**`, `[+8] va`, `[+0x10] buf`, `[+0x18] size`, `[+0x20] **DirBase**` | 数据写进 `buf` |
| `0x222004` 虚拟写 | `0x28` | 同上 | 从 `buf` 写进目标进程 |
| `0x222010` 取 System EPROCESS | `8` | 无 | `+0x00` = SYSTEM 进程的 EPROCESS |
| `0x222014` 取进程映象基址 | `0x18` | `[+0] pid`, `[+0x10] size≠0` | `+0x08` = 该进程的映像基址 |

### 之前为什么会一直失败

1. **`0x222000/0x222004` 的第 1 个字段是 PID,不是 CR3。**
   驱动拿到 PID 后自己 `PsLookupProcessByProcessId` 再读
   `EPROCESS+0x28` 作为 DirBase。我此前一直往里传 CR3,
   而 `[+0x20]` 被驱动当成"必须非 0"的哨兵位 —— 上一版往那里塞的
   恰好是 CR3,看着能用,但 `[+0]` 的 PID 是 0,于是每条请求都被
   驱动以 `0xC0000022` 直接拒掉。这条路从一开始就没通过。
2. **`0x22200C` 里没有任何权限检查。**
   它就是调 `ZwQuerySystemInformation(0xb)`,返回 0 表示"模块列表里
   没匹配到"。前几版把它归因于 SeDebugPrivilege,并让程序去重开令牌,
   既没解决问题,又把进程的权限/完整性改坏了(现在默认不再动令牌)。
3. **`0x222040` 的结果在 `out+0x20`,不是 `out+0x10`。**
   驱动读的是 `base+offset`、`+0x10`、`+0x20` 三个位置,只有
   `buffer[2]`(即 `+(offset+0x10)`)非 0 才把 5 个 QWORD 回写到
   `out+0x10..0x38`。所以请求要用 `base = addr-0x10`、`offset = 0`,
   答案再去 `out+0x20` 取 —— 这样即使目标值是 0 也能读对。

### 现在的调用链(全部经过实测模拟)

```
内核基址   NtQuerySystemInformation(11) 用户态直接拿(不需要 IOCTL、不需要特权)
System EP  0x222010 → 驱动自己 PsLookupProcessByProcessId(4)
目标 EP    从 System EP 沿 ActiveProcessLinks 走,每一跳校验后才用;
           命中后用 0x222014 的映像基址交叉确认
进程读写   0x222000 / 0x222004,只传 PID + 用户态地址 + 我们自己的缓冲区
```

`0x222040` 只在读 EPROCESS 字段时使用,并且有两条硬约束:
窗口 `[addr-0x10, addr+0x18]` 不能跨页;地址必须是规范内核地址。

> **注意:`ntoskrnl` 的基址不保证 2MB 对齐。** 实测这台机器是
> `0xFFFFF80461E13000`(4KB 对齐)。任何"必须 2MB 对齐"的校验都会把它误判为
> 布局错误 —— 旧版本正是因为这条把唯一正确的答案扔掉了。

## 3.2 修改记录

* **✅ v10 已在真机验证通过 (Win10 21H2 / 19044, signed.sys)**
  ```
  [+] ntoskrnl base: 0xFFFFF80461E13000 (NtQuerySystemInformation)
  [i] EPROCESS 0xFFFFD58C84446080: pid +0x440, DirBase 0x4D91E000
  [3/5] EPROCESS/CR3  : 0x4D91E000   (pid 4000, this process)
  [4/5] page-table R/W: read b'MZ' at 0x7FF7140E0000 -- OK
  [5/5] write test   : wrote+verified b'WINNOTIFY-SELFTEST' at 0x21D79760000
  [OK] all safe checks passed
  ```
  五段全过:**取基址 / 取位 System EPROCESS / 遍历 EPROCESS 拿 CR3 /
  按 CR3 读用户内存 / 按 CR3 写回并校验**。全程零蓝屏。
  这一版之前踩过的三个坑(供以后排查参考):
  1. `_RTL_PROCESS_MODULE_INFORMATION` stride 是 `0x128`、`ImageBase` 在 `+0x10`
     (`0x130` / `+0x00` 都是错的);
  2. `ntoskrnl` **不保证 2MB 对齐**,本机是 4KB 对齐的 `0xFFFFF80461E13000`;
  3. `0x222000/0x222004` 的 `in[0x20]` 是**真正的 DirBase**,驱动拿它翻页表,
     传常量或 0 只会得到 `STATUS_ACCESS_DENIED`。

* **v10 (2026-11-23)**: **`in[0x20]` 是 CR3,不是哨兵位**。
  反汇编 `sub_2a24`:
  ```asm
  140002a60: cmp  qword ptr [rcx+0x20], 0
  140002a65: je   -> 0xC0000022          ; 只检查非 0
  140002a7a: mov  rdx, qword ptr [rdi+0x20]  ; 然后拿它当 DirBase
  140002a81: call 0x140002c10                ; 去翻页表 PML4->PDPT->PD->PT
  ```
  我之前把它读成"必须非 0 的哨兵",塞了常量 `1`。驱动于是拿物理地址 0
  翻页表,每条请求返回 **`STATUS_ACCESS_DENIED`(你看到的 WinError 5)**。
  现在 `_vioclt_packet()` 必须带真实 DirBase:从 `EPROCESS+0x28` 取,
  并且 `_vet_ioctl_packet()` 会拦下任何不像页表基址的值。
  因此 `read_memory`/`write_memory` 现在两条路径都要 CR3(以前只有回退路径查)。
* **v10 附带**:`_RTL_PROCESS_MODULE_INFORMATION.ImageSize` 是
  **`+0x18` 处的 DWORD**,不是 8 字节(`+0x1C` 是 `Flags`)。
  你日志里 `ImageSize 0x0880408001046000` 就是两个 DWORD 拼在一起:
  真值是 `0x01046000`(16 MB,合理),`Flags = 0x08804080`。
  修正后模块列表这条路也不再误报。
  另外**没有**去校验 `Flags` 的位 —— 驱动只读 `+0x26` 和 `+0x10`,
  二进制里验证不出来的东西不该写成断言(2MB 对齐就是这么错的)。

* **v9 (2026-11-23)**: **`ntoskrnl` 不是 2MB 对齐的 —— 我的校验把它判死了**。
  你贴的日志里 `module list gave 0xFFFFF80461E13000` 是个**正确答案**:
  合法内核地址、名字精确匹配 `\ntoskrnl.exe`、低 12 位为 0(4KB 对齐)。
  但我旧代码要求 `(base & 0x1FFFFF) == 0`,于是把它当成"布局错"扔掉,
  又退回那个坏掉的 `0x22200C`。现在改成按**自洽性**验证:
  * 在规范内核区间(`>= 0xFFFF800000000000`)且页对齐;
  * `ImageSize` 在合理区间;
  * 路径以请求的模块名结尾。
  * 顺带把 `_system_module_information()` 的返回值加上 `ImageSize`,
    并让 `kernel_base_from_system_info()` 失败时**抛异常带原因**
    (以前是静默返回垃圾 -> 静默 fallback -> 你只看到下游那个 `0x22200C` 报错)。
* **v9 的另一半:内核基址不再必需**。`0x222010` 直接给 System EPROCESS,
  `0x222000/0x222004` 只吃 PID,所以整条 read/write 链**不依赖任何内核地址**。
  `start()` 拿不到基址时只打印一行提示继续跑,不再中止;
  `find_system_eprocess()` 的 `PsInitialSystemProcess` 回退在无基址时直接跳过
  (否则会拿 `kernel_base + offset` = 用户态地址去给驱动解引用 —— 这是个真 bug)。

* **v8 (2026-11-23)**: **按 `signed.sys` 本体反汇编重写 IOCTL 层**。
  拿你给的那个仓库里的 `signed.sys`(sha256 `4dc3a03a…508e0f`)
  逐条指令核对,发现三个致命 bug:
  1. `0x222000/0x222004` 的 `[+0]` 是 **PID**,`[+0x20]` 是**必须非 0 的哨兵**,
     不是 CR3 —— 之前每条虚拟读写请求都被驱动以 `0xC0000022` 拒掉;
  2. `0x222040` 的返回值在 `out+0x20`(驱动写的是
     `out+0x10 = *(base+offset)`、`out+0x20 = *(base+offset+0x10)`),
     之前从 `out+0x10` 取,读出来的永远是"目标地址前 0x10 字节";
  3. `0x22200C` **没有任何权限检查**,之前关于 SeDebugPrivilege 的整条
     推断是错的(`ensure_debug_privilege` 默认改为 **false**,不再重开令牌)。
  同时新增两条**不需要猜地址**的路径:
  * `0x222010` 直接拿 System EPROCESS(驱动内部 `PsLookupProcessByProcessId(4)`);
  * `0x222014` 拿任意进程的映像基址,用来交叉确认 EPROCESS 命中。
  因此 `PsInitialSystemProcess` 偏移(`0xCFC420` 那套)**不再是必需项**,
  EPROCESS 也不再靠"扫一片内存找 pid"来猜。
* **另修一个隐藏 bug**:`winnotify.py` 里 `class WinNotify` 被整段重复了
  一次(早期替换脚本写坏的),后一份覆盖前一份,所以某些改动一直"没生效"。
  已删除重复段(文件从 3016 行降到约 1950 行)。

* **v7 (2026-11-23)**: **修复"令牌里根本没有 SeDebugPrivilege"**。
  之前 `token_privileges()` 解析 `TOKEN_PRIVILEGES` 时把数组起点写成 `+8`,
  实际应为 `+4`(`DWORD PrivilegeCount` 后紧跟 `LUID_AND_ATTRIBUTES`),
  所以把所有权限都误报成"不存在"。修好解析后:
  * 优先用 **不需要任何令牌特权** 的 `NtQuerySystemInformation` 取内核基址
    (`kernel_base_via_system_info`, 默认开),不再依赖 `0x22200C`;
  * 检测到非提升令牌(中完整性)时**自动弹 UAC 重新以管理员启动**
    (`relaunch_elevated`, `ShellExecuteExW runas`),`--no-elevate` 可关闭;
  * `privcheck` 现在会打印 elevation type / 完整性级别 / 权限数量;
  * 错误信息直接指向"用管理员运行"。
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
