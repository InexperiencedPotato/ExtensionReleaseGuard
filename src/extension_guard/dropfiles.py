"""Drag-and-drop of files onto the window, with no third-party dependency.

Tk 8.6 cannot receive file drops, and ``tkinterdnd2`` would need its native tkdnd binaries
bundled into the executable. Windows already delivers ``WM_DROPFILES`` to any window that opts in
with ``DragAcceptFiles``, so each Tk widget window is subclassed through ``ctypes`` to read the
dropped paths (Unicode-safe) and hand them to a callback on the Tk thread.

Limits: this is the legacy shell drop, so there is no hover highlight while dragging (only on
drop), and it does not work when the app runs elevated and Explorer does not (a Windows
restriction). If anything fails, :attr:`DropFiles.active` stays ``False`` and Browse still works.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional, Tuple

WM_DROPFILES = 0x0233
WM_COPYGLOBALDATA = 0x0049
WM_NCDESTROY = 0x0082
GWL_WNDPROC = -4
MSGFLT_ALLOW = 1
GA_ROOT = 2
MAX_DROPPED = 16  # paths read from one drop; more than one is rejected anyway


def validate_drop(paths: List[str]) -> Tuple[Optional[str], str]:
    """``(path, "")`` for exactly one existing ``.zip`` file, else ``(None, reason)``."""
    if not paths:
        return None, "Nothing was dropped."
    if len(paths) > 1:
        return None, "Drop one ZIP file at a time."
    path = paths[0]
    name = os.path.basename(path.rstrip("\\/")) or path
    if os.path.isdir(path):
        return None, f"{name} is a folder. Zip the extension folder first, then drop the .zip."
    if not path.lower().endswith(".zip"):
        return None, f"{name} is not a .zip file."
    if not os.path.isfile(path):
        return None, f"{name} could not be found."
    return path, ""


class DropFiles:
    """Subclasses widget windows of one Tk root so dropped files reach ``on_paths(list_of_str)``."""

    def __init__(self, root, on_paths: Callable[[List[str]], None]):
        self._root = root
        self._on_paths = on_paths
        self._previous: Dict[int, int] = {}  # hwnd -> original window procedure
        self._proc = None
        self._api = None
        self.active = False

    # ---- setup / teardown -------------------------------------------------

    def install(self) -> bool:
        """Start accepting drops on the whole window; ``False`` when unavailable."""
        if sys.platform != "win32":
            return False
        try:
            self._api = _load_api()
            self._proc = self._api.WNDPROC(self._wndproc)
            self.hook_tree(self._root)
            top = self._api.user32.GetAncestor(self._root.winfo_id(), GA_ROOT)
            if top:
                self._hook(top)
            self.active = bool(self._previous)
        except Exception:  # noqa: BLE001 - drop support is optional; never break the app over it
            self.uninstall()
        return self.active

    def uninstall(self) -> None:
        """Restore every original window procedure (call before the window is destroyed)."""
        api = self._api
        if api is not None:
            for hwnd, previous in list(self._previous.items()):
                try:
                    if api.user32.IsWindow(hwnd):
                        api.user32.SetWindowLongPtrW(hwnd, GWL_WNDPROC, previous)
                        api.shell32.DragAcceptFiles(hwnd, False)
                except Exception:  # noqa: BLE001
                    pass
        self._previous.clear()
        self.active = False

    def hook_tree(self, widget) -> None:
        """Accept drops on *widget* and all of its descendants (new widgets must be hooked too)."""
        if self._proc is None:
            return
        try:
            self._hook(widget.winfo_id())
            for child in widget.winfo_children():
                self.hook_tree(child)
        except Exception:  # noqa: BLE001 - a widget destroyed mid-walk
            pass

    def _hook(self, hwnd: int) -> None:
        api = self._api
        if not hwnd or hwnd in self._previous:
            return
        previous = api.user32.SetWindowLongPtrW(hwnd, GWL_WNDPROC, api.as_pointer(self._proc))
        if not previous:
            return
        self._previous[hwnd] = previous
        api.shell32.DragAcceptFiles(hwnd, True)
        # An elevated app would otherwise never see drops from a normal Explorer.
        for msg in (WM_DROPFILES, WM_COPYGLOBALDATA):
            api.user32.ChangeWindowMessageFilterEx(hwnd, msg, MSGFLT_ALLOW, None)

    # ---- window procedure -------------------------------------------------

    def _wndproc(self, hwnd, msg, wparam, lparam):
        api = self._api
        if msg == WM_DROPFILES:
            try:
                paths = api.query_files(wparam)
            finally:
                api.shell32.DragFinish(wparam)
            try:
                self._root.after(0, self._on_paths, paths)  # same thread; run outside the message handler
            except Exception:  # noqa: BLE001 - the window may be going away
                pass
            return 0
        previous = self._previous.get(hwnd)
        if previous is None:
            return api.user32.DefWindowProcW(hwnd, msg, wparam, lparam)
        result = api.user32.CallWindowProcW(previous, hwnd, msg, wparam, lparam)
        if msg == WM_NCDESTROY:
            self._previous.pop(hwnd, None)
        return result


def _load_api() -> SimpleNamespace:
    """The few Win32 calls used, with explicit signatures (64-bit safe)."""
    import ctypes
    from ctypes import wintypes

    api = SimpleNamespace()
    api.user32 = user32 = ctypes.WinDLL("user32", use_last_error=True)
    api.shell32 = shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    LRESULT = ctypes.c_ssize_t
    api.WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
    user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
    user32.SetWindowLongPtrW.restype = ctypes.c_void_p
    user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.CallWindowProcW.restype = LRESULT
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = LRESULT
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    user32.IsWindow.argtypes = [wintypes.HWND]
    user32.ChangeWindowMessageFilterEx.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.DWORD, ctypes.c_void_p]
    shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
    shell32.DragFinish.argtypes = [ctypes.c_void_p]
    shell32.DragQueryFileW.argtypes = [ctypes.c_void_p, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
    shell32.DragQueryFileW.restype = wintypes.UINT
    api.as_pointer = lambda proc: ctypes.cast(proc, ctypes.c_void_p)

    def query_files(hdrop) -> List[str]:
        count = min(shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0), MAX_DROPPED + 1)
        paths = []
        for index in range(count):
            length = shell32.DragQueryFileW(hdrop, index, None, 0)
            buffer = ctypes.create_unicode_buffer(length + 1)
            shell32.DragQueryFileW(hdrop, index, buffer, length + 1)
            paths.append(buffer.value)
        return paths

    api.query_files = query_files
    return api
