# ce1 — WinNotify 内核桥 / Python 版

`src/` 是 Cheat Engine 的 Pascal 补丁(内核桥 `PhysicalMemory.pas` / `KernelBridge.pas`)。
`py/` 是**同一套逻辑的纯 Python 实现**,并打包成单个 `.exe`:

```
py/
  winnotify.py   驱动加载 + IOCTL + EPROCESS 遍历 + CR3 页表读写
  cli.py         .exe 入口(read / write / freeze / selftest)
  build.ps1      PyInstaller 打包脚本
  winnotify.json.example   偏移/IOCTL 覆盖配置
  README.md      用法与完整字段说明
```

## 快速开始

```powershell
cd py
powershell -ExecutionPolicy Bypass -File .\build.ps1     # -> dist\winnotify-cli.exe
```

把 `WinNotify.sys` 放到 exe 同目录,以管理员运行:

```bat
:: 进程 + 阳光地址 + 新值
winnotify-cli.exe PlantsVsZombies.exe 0x0019A5B8 999

:: 先确认地址
winnotify-cli.exe read PlantsVsZombies.exe 0x0019A5B8 -n 16

:: 锁定阳光
winnotify-cli.exe freeze PlantsVsZombies.exe 0x0019A5B8 999 -i 0.1

:: 全链路自检(驱动 -> ntoskrnl -> EPROCESS -> CR3 -> 读写)
winnotify-cli.exe selftest
```

默认 IOCTL 码与缓冲区布局与 `src/PhysicalMemory.pas` **逐字节一致**
(`0x22200C/40/44/50/54`),系统版本/驱动不同时改 `winnotify.json` 即可,
详见 [`py/README.md`](py/README.md)。

## 免责声明

仅供本机、自有进程的学习与研究使用。
