#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Admin Runner (Windows)

功能:
- 启动后自动尝试提权为管理员(UAC 提示)。
- 隐藏控制台窗口(不再创建任务栏托盘图标)。
- 读取程序根目录下 run.txt(每行一个程序命令,可包含参数),以管理员身份启动。
- 每 15 秒检测一次进程是否仍在运行,如果不在则重新以管理员启动,启动后延迟 10 秒继续检测。

说明:
- 仅支持 Windows;使用少量 Win32 API(通过 ctypes)。
"""

import ctypes
import os
import shlex
import subprocess
import sys
import time
from ctypes import wintypes
import sentry_sdk
import atexit
import signal

# 捕获未处理异常，确保上报
def _unhandled_excepthook(exc_type, exc_value, exc_traceback):
    try:
        sentry_sdk.capture_exception(exc_value)
        sentry_sdk.flush(timeout=2.0)
    except Exception:
        pass
    # 继续调用原始 excepthook，避免吞掉默认行为
    try:
        if hasattr(sys, "__excepthook__"):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
    except Exception:
        pass

sys.excepthook = _unhandled_excepthook

sentry_sdk.init(
    dsn="https://b6e0d79236579c2a9ca60167acc58ce5@o4510289605296128.ingest.de.sentry.io/4510289610670160",
    traces_sample_rate=1.0,
    enable_logs=True,
    shutdown_timeout=3.0,
)

APP_NAME = "Admin Tray Runner"
RUN_LIST_FILE = "run.txt"
CHECK_INTERVAL_SEC = 15
RESTART_DELAY_SEC = 10

# Basic Sentry tags/context
try:
    sentry_sdk.set_tag("app_name", APP_NAME)
    sentry_sdk.set_tag("frozen", bool(getattr(sys, "frozen", False)))
    sentry_sdk.set_tag("pid", os.getpid())
    sentry_sdk.set_context(
        "runtime",
        {
            "cwd": os.getcwd(),
            "exe": sys.executable,
            "argv": sys.argv,
        },
    )
except Exception:
    pass


def _sentry_msg(message: str, extra: dict | None = None):
    try:
        if extra:
            # 使用 logger API 记录日志,并将 extra 转换为字符串附加到消息中
            details_str = ", ".join([f"{k}={v}" for k, v in extra.items()])
            sentry_sdk.logger.info(f"{message} [{details_str}]")
        else:
            sentry_sdk.logger.info(message)
    except Exception:
        pass


# Ensure we record process exit regardless of where it occurs
try:
    atexit.register(lambda: _sentry_msg("应用进程退出(atexit)", {"pid": os.getpid()}))
except Exception:
    pass


# ---- Signal handlers for graceful shutdown ----
def handle_exit_signal(signum, frame):
    """处理进程终止信号"""
    try:
        signal_name = "UNKNOWN"
        if signum == signal.SIGTERM:
            signal_name = "SIGTERM"
        elif signum == signal.SIGINT:
            signal_name = "SIGINT"
        elif signum == signal.SIGBREAK:
            signal_name = "SIGBREAK"
        
        _sentry_msg(
            "收到终止信号，程序即将退出",
            {
                "signal": signal_name,
                "signal_num": signum,
                "pid": os.getpid(),
                "source": "任务管理器或系统终止"
            }
        )
        sentry_sdk.flush(timeout=2)  # 等待最多2秒确保日志发送
    except Exception:
        pass
    finally:
        sys.exit(0)


# 注册信号处理器
try:
    # SIGTERM: 任务管理器结束进程时通常会发送此信号
    signal.signal(signal.SIGTERM, handle_exit_signal)
    # SIGINT: Ctrl+C（虽然控制台隐藏了，但以防万一）
    signal.signal(signal.SIGINT, handle_exit_signal)
    # SIGBREAK: Windows 特有的 Ctrl+Break 信号
    signal.signal(signal.SIGBREAK, handle_exit_signal)
except Exception:
    pass


# ---- Elevation helpers ----
class ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_SHOWNORMAL = 1

# Use explicit WinDLL instances and retrieve functions via getattr to reduce IDE warnings
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Resolve needed WinAPI procedures (avoid attribute access warnings by using getattr)
_IsUserAnAdmin = getattr(shell32, "IsUserAnAdmin")
_IsUserAnAdmin.restype = wintypes.BOOL

_ShellExecuteExW = getattr(shell32, "ShellExecuteExW")
_ShellExecuteExW.restype = wintypes.BOOL

_GetConsoleWindow = getattr(kernel32, "GetConsoleWindow")
_GetConsoleWindow.restype = wintypes.HWND

_ShowWindow = getattr(user32, "ShowWindow")
_ShowWindow.restype = wintypes.BOOL

_WaitForSingleObject = getattr(kernel32, "WaitForSingleObject")
_WaitForSingleObject.restype = wintypes.DWORD

_GetExitCodeProcess = getattr(kernel32, "GetExitCodeProcess")
_GetExitCodeProcess.restype = wintypes.BOOL

_CloseHandle = getattr(kernel32, "CloseHandle")
_CloseHandle.restype = wintypes.BOOL

# Console control handler (Task Manager close/logoff/shutdown)
HandlerRoutine = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
CTRL_EVENTS = {
    0: "CTRL_C_EVENT",
    1: "CTRL_BREAK_EVENT",
    2: "CTRL_CLOSE_EVENT",
    5: "CTRL_LOGOFF_EVENT",
    6: "CTRL_SHUTDOWN_EVENT",
}
_SetConsoleCtrlHandler = getattr(kernel32, "SetConsoleCtrlHandler")
_SetConsoleCtrlHandler.restype = wintypes.BOOL
_SetConsoleCtrlHandler.argtypes = [HandlerRoutine, wintypes.BOOL]

def _make_console_ctrl_handler():
    def _handler(ctrl_type):
        try:
            name = CTRL_EVENTS.get(int(ctrl_type), f"UNKNOWN({ctrl_type})")
            _sentry_msg(
                "收到控制台关闭事件，程序即将退出",
                {
                    "event": name,
                    "code": int(ctrl_type),
                    "pid": os.getpid(),
                    "提示": "可能来自任务管理器的结束任务/用户注销/关机"
                },
            )
            try:
                sentry_sdk.flush(timeout=1.5)
            except Exception:
                pass
        except Exception:
            pass
        # 返回 False 交给系统默认处理，避免阻止关闭
        return False
    return HandlerRoutine(_handler)

# 保持对回调的引用，避免被 GC
_CONSOLE_CTRL_HANDLER_REF = _make_console_ctrl_handler()
try:
    _SetConsoleCtrlHandler(_CONSOLE_CTRL_HANDLER_REF, True)
except Exception:
    pass


def is_user_admin() -> bool:
    try:
        return bool(_IsUserAnAdmin())
    except Exception:
        return False

# 提权
def relaunch_as_admin():
    """Relaunch current program with admin privileges via ShellExecuteExW(runas).

    Handles both normal Python script execution and frozen (PyInstaller) executables.
    """
    try:
        sentry_sdk.add_breadcrumb(category="elevation", message="尝试通过 ShellExecuteExW 进行 UAC 提权", level="info")
        sentry_sdk.logger.info("非管理员，正在尝试提权")
    except Exception:
        pass

    # Build parameters (preserve original argv except argv[0])
    params = []
    for arg in sys.argv[1:]:
        # Quote only when needed; keep Windows-friendly quoting
        if " " in arg or "\t" in arg or '"' in arg:
            params.append(f'"{arg}"')
        else:
            params.append(arg)
    param_str = " ".join(params)

    script_path = os.path.abspath(sys.argv[0])

    # In frozen mode (PyInstaller), sys.executable is the EXE path already.
    # We must set lpFile to the EXE and NOT pass the exe path again as a parameter
    # to avoid recursion like: exe "exe" args.
    is_frozen = getattr(sys, "frozen", False)

    sei = ShellExecuteInfo()
    sei.cbSize = ctypes.sizeof(ShellExecuteInfo)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.hwnd = None
    sei.lpVerb = "runas"  # trigger UAC
    if is_frozen:
        sei.lpFile = script_path
        sei.lpParameters = param_str
        sei.lpDirectory = os.path.dirname(script_path)
    else:
        # Non-frozen: launch through the Python interpreter
        sei.lpFile = sys.executable
        # Pass the script path as the first argument followed by the rest
        if param_str:
            sei.lpParameters = f'"{script_path}" {param_str}'
        else:
            sei.lpParameters = f'"{script_path}"'
        sei.lpDirectory = os.path.dirname(script_path)
    sei.nShow = SW_SHOWNORMAL

    if not _ShellExecuteExW(ctypes.byref(sei)):
        try:
            sentry_sdk.logger.error("提权失败")
        except Exception:
            pass
        raise ctypes.WinError(ctypes.get_last_error())

    # Wait for the elevated child to finish, so this non-admin instance doesn't exit immediately.
    try:
        hProcess = sei.hProcess
        INFINITE = 0xFFFFFFFF
        _WaitForSingleObject(hProcess, INFINITE)
        exit_code = wintypes.DWORD()
        if _GetExitCodeProcess(hProcess, ctypes.byref(exit_code)):
            code = exit_code.value
        else:
            code = 0
    finally:
        try:
            _CloseHandle(sei.hProcess)
        except Exception:
            pass

    try:
        sentry_sdk.logger.info("提权父进程在子进程退出后结束")
        sentry_sdk.flush()
    except Exception:
        pass

    sys.exit(code)


# ---- Console hide ----
def hide_console_window():
    try:
        hWnd = _GetConsoleWindow()
        if hWnd:
            _ShowWindow(hWnd, 0)  # SW_HIDE = 0
            _sentry_msg("控制台已隐藏")
    except Exception:
        pass


# ---- Tray icon removed as per user request ----
# 程序将仅隐藏控制台，不再创建系统托盘图标。


# ---- Process management ----
class ManagedProcess:
    def __init__(self, cmd_line: str):
        self.cmd_line = cmd_line
        self.process: subprocess.Popen | None = None
        self.start_count = 0  # 新增:记录启动次数

    def start(self):
        args = shlex.split(self.cmd_line, posix=False)
        if not args:
            return
        exe = args[0]
        # Normalize and set working dir
        exe_path = exe.strip('"')
        cwd = os.path.dirname(exe_path) if os.path.isabs(exe_path) else None
        creationflags = 0x00000008  # DETACHED_PROCESS
        try:
            # We're already elevated; start child normally (it inherits admin token)
            self.process = subprocess.Popen(
                args,
                cwd=cwd or None,
                creationflags=creationflags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
            try:
                _sentry_msg(
                    "受管进程已启动",
                    {
                        "cmd": self.cmd_line,
                        "pid": getattr(self.process, "pid", None),
                        "cwd": cwd,
                    },
                )
            except Exception:
                pass
        except Exception as e:
            print(f"Failed to start: {self.cmd_line} -> {e}")
            try:
                sentry_sdk.capture_exception(
                    e,
                    contexts={"details": {"cmd": self.cmd_line, "error": str(e)}}
                )
            except Exception:
                pass
            self.process = None

    def is_running(self) -> bool:
        if self.process is None:
            return False
        return self.process.poll() is None

    def ensure_running(self) -> bool:
        if not self.is_running():
            self.start()
            if self.is_running():
                self.start_count += 1
                if self.start_count == 1:
                    _sentry_msg("受管进程已首次启动", {"cmd": self.cmd_line, "pid": getattr(self.process, "pid", None)})
                else:
                    _sentry_msg("受管进程已自动重启", {"cmd": self.cmd_line, "pid": getattr(self.process, "pid", None), "restart_count": self.start_count - 1})
                time.sleep(RESTART_DELAY_SEC)
                return True
            else:
                _sentry_msg("受管进程启动失败", {"cmd": self.cmd_line})
                return False
        return True


def read_run_list(base_dir: str) -> list[str]:
    run_path = os.path.join(base_dir, RUN_LIST_FILE)
    commands: list[str] = []
    if not os.path.exists(run_path):
        # Create a template file for user convenience
        with open(run_path, "w", encoding="utf-8") as f:
            f.write(
                "# 每行一个要启动的程序命令（可含参数）。例如：\n"
                "# C:\\Windows\\System32\\notepad.exe\n"
                "# \"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe\" --intf qt\n"
            )
        return commands
    with open(run_path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            commands.append(s)
    return commands


def main():
    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

    # App start event (pre-elevation)
    _sentry_msg(
        "应用启动",
        {
            "admin": is_user_admin(),
            "argv": sys.argv,
            "base_dir": base_dir,
        },
    )

    # Ensure elevation
    if not is_user_admin():
        relaunch_as_admin()
        return  # safety

    # Post-elevation start event
    _sentry_msg("应用已以管理员权限运行", {"pid": os.getpid(), "exe": sys.executable})

    # Hide console
    hide_console_window()

    # Read run list and start processes
    commands = read_run_list(base_dir)
    _sentry_msg("运行列表已加载", {"count": len(commands)})
    managed = [ManagedProcess(cmd) for cmd in commands]
    for mp in managed:
        mp.ensure_running()

    # Monitoring started
    _sentry_msg("监控已启动", {"interval_sec": CHECK_INTERVAL_SEC})

    # Monitor loop
    try:
        while True:
            try:
                for mp in managed:
                    mp.ensure_running()
            except Exception as e:
                # Ensure any unexpected error in one cycle doesn't stop the continuous monitoring
                try:
                    sentry_sdk.capture_exception(e)
                except Exception:
                    pass
            time.sleep(CHECK_INTERVAL_SEC)
    except KeyboardInterrupt:
        _sentry_msg("收到键盘中断(Ctrl+C)")
    finally:
        _sentry_msg("应用退出(finally)")
        try:
            sentry_sdk.flush()
        except Exception:
            pass


if __name__ == "__main__":
    if os.name != "nt":
        print("This script is intended to run on Windows only.")
        sys.exit(1)
    main()
