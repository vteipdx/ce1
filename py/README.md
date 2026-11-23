# py/ -- WinNotify.sys → Python → .exe

Python twin of `src/PhysicalMemory.pas` + `src/KernelBridge.pas`:
same IOCTLs (`0x22200C / 0x222040 / 0x222044 / 0x222050 / 0x222054`),
same packet layouts, same EPROCESS walk → target CR3 → page-table R/W.

```
py/
  winnotify.py            内核层: 驱动加载 + IOCTL + EPROCESS 遍历 + 进程读写
  cli.py                  CLI  (.exe 入口)
  winnotify.json.example  偏移/IOCTL 覆盖配置 (可选, 放在 exe 旁边)
  README.md               本文
  build.ps1               PyInstaller 打包脚本
  requirements-build.txt  打包依赖
```

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

:: 自检: 驱动加载 → ntoskrnl base → EPROCESS 遍历 → CR3 页表读写
winnotify-cli.exe selftest
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

| 字段 | 含义 | 默认 (PhysicalMemory.pas) |
|---|---|---|
| `ioctl_info/read/write/phys_read/phys_write` | IOCTL 码 | `0x22200C/40/44/50/54` |
| `device_path` | 设备符号链接 | `\\.\WinNotify` |
| `service_name` | 服务名 | `WinNotify` |
| `eprocess_links/pid/dtb` | EPROCESS 偏移 | `0x448/0x440/0x28` |
| `ps_initial_system_offsets` | PsInitialSystemProcess 相对 ntoskrnl 的偏移候选 | 4 个候选 |
| `read_bias/read_result_offset` | READ IOCTL 的“地址-0x10”怪癖 | `0x10/0x20` |
| `info_result_offset` | INFO IOCTL 返回内核基址的位置 | `0x10` |
| `keep_service` | 退出时是否保留驱动服务 | `true` |

`selftest` 会逐段报告哪一步失败,对应改哪个字段。

> `selftest` 默认拿**自己这个进程**做读写验证(不需要游戏在跑);
> 想测别的进程用 `winnotify-cli.exe selftest --pid 1234`
> 或 `... selftest --pid PlantsVsZombies.exe`。

## 3.1 修改记录

* **v2 (2026-11-23)**: 修复首次打包后 `selftest` 直接崩在 import 的问题。
  `LookupPrivilegeValueW` / `AdjustTokenPrivileges` / `OpenProcessToken` /
  `OpenSCManagerW` 等其实在 **advapi32.dll**,之前错绑到 kernel32 上,
  打包成 exe 后 `function 'LookupPrivilegeValueW' not found`。
  现在按 DLL 分组声明原型、逐个 `try/except` 绑定,缺函数不会中断 import;
  运行时任何异常都打印成一行中文友好的 `[ERROR]`,不再抛 traceback。
* 输出全部改为 ASCII,避免 cp936 控制台乱码/编码异常。

## 4. 说明 / 边界

* 这是 `src/PhysicalMemory.pas` 的**纯 Python 移植**,不是新驱动:驱动验证、加载方式
  仍由 WinNotify.sys 自己决定;工具只负责 `CreateService + StartService + DeviceIoControl`。
* 写内存走“驱动按 CR3 翻页表 → 读整页 → 改 → 写回”,所以不需要 `OpenProcess` 句柄,
  也不受目标进程句柄保护影响;但**不要**拿它改与游戏完整性校验相关的代码段。
* 只在本机、你自己有权限的进程上用。测试建议先在 `selftest` 通过后再动游戏。
