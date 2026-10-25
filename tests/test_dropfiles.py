import ctypes
import os
import shutil
import sys
import tempfile
import tkinter
import unittest
from ctypes import wintypes

from src.extension_guard import dropfiles as D


class TestValidateDrop(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))

    def touch(self, name):
        path = os.path.join(self.d, name)
        with open(path, "wb") as fh:
            fh.write(b"PK")
        return path

    def test_accepts_one_zip_including_spaces_unicode_and_any_case(self):
        for name in ("ext.zip", "my extension (v2).zip", "επέκταση-日本語.zip", "UPPER.ZIP"):
            path = self.touch(name)
            self.assertEqual(D.validate_drop([path]), (path, ""), name)

    def test_rejections_have_clear_reasons(self):
        txt, folder = self.touch("a.txt"), os.path.join(self.d, "folder.zip")
        os.mkdir(folder)  # a folder, even one named like a zip
        cases = [
            ([], "Nothing"),
            ([self.touch("a.zip"), self.touch("b.zip")], "one ZIP"),
            ([txt], "not a .zip"),
            ([folder], "folder"),
            ([os.path.join(self.d, "gone.zip")], "could not be found"),
            ([os.path.join(self.d, "no extension")], "not a .zip"),
        ]
        for paths, fragment in cases:
            path, reason = D.validate_drop(paths)
            self.assertIsNone(path)
            self.assertIn(fragment, reason)

    def test_messages_name_only_the_file(self):
        _, reason = D.validate_drop([self.touch("a.txt")])
        self.assertNotIn(self.d, reason)


@unittest.skipUnless(sys.platform == "win32", "WM_DROPFILES is Windows-only")
class TestWindowsDrop(unittest.TestCase):
    """Sends a real WM_DROPFILES (with a genuine HDROP) to our own window; no desktop input is involved."""

    def setUp(self):
        self.root = tkinter.Tk()
        self.root.withdraw()
        self.addCleanup(self._destroy)
        self.got = []
        self.drop = D.DropFiles(self.root, self.got.append)
        self.assertTrue(self.drop.install())

    def _destroy(self):
        self.drop.uninstall()
        self.root.destroy()

    @staticmethod
    def hdrop(paths):
        data = ("\0".join(paths) + "\0\0").encode("utf-16-le")
        header = (ctypes.c_byte * 20)()
        ctypes.memmove(header, (20).to_bytes(4, "little") + bytes(12) + (1).to_bytes(4, "little"), 20)  # pFiles, pt, fNC, fWide
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        handle = kernel32.GlobalAlloc(0x42, 20 + len(data))
        ptr = kernel32.GlobalLock(handle)
        ctypes.memmove(ptr, bytes(header), 20)
        ctypes.memmove(ptr + 20, data, len(data))
        kernel32.GlobalUnlock(handle)
        return handle

    def send_drop(self, paths, hwnd=None):
        user32 = ctypes.WinDLL("user32")
        user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_void_p, wintypes.LPARAM]
        user32.SendMessageW.restype = ctypes.c_ssize_t
        self.root.update()
        target = hwnd or self.root.winfo_id()
        user32.SendMessageW(target, D.WM_DROPFILES, self.hdrop(paths), 0)
        self.root.update()  # runs the after(0) callback

    def test_paths_arrive_intact_on_the_tk_thread(self):
        paths = [r"C:\Users\Test User\Desktop\επέκταση 日本語.zip"]
        self.send_drop(paths)
        self.assertEqual(self.got, [paths])

    def test_several_files_are_all_reported(self):
        paths = [r"C:\a.zip", r"C:\b b.zip"]
        self.send_drop(paths)
        self.assertEqual(self.got, [paths])

    def test_child_widget_windows_accept_drops_too(self):
        frame = tkinter.Frame(self.root)
        frame.pack()
        self.root.update()
        self.drop.hook_tree(frame)
        self.send_drop([r"C:\c.zip"], hwnd=frame.winfo_id())
        self.assertEqual(self.got, [[r"C:\c.zip"]])

    def test_other_messages_still_reach_the_original_procedure(self):
        self.root.deiconify()
        self.root.update()
        self.root.title("still works")
        self.root.geometry("300x200+10+10")
        self.root.update()
        self.assertEqual(self.root.title(), "still works")
        self.assertEqual(self.root.winfo_width(), 300)

    def test_uninstall_restores_and_stops_delivery(self):
        self.drop.uninstall()
        self.assertFalse(self.drop.active)
        self.send_drop([r"C:\d.zip"])
        self.assertEqual(self.got, [])

    def test_install_twice_is_harmless(self):
        count = len(self.drop._previous)
        self.drop.hook_tree(self.root)
        self.assertEqual(len(self.drop._previous), count)


if __name__ == "__main__":
    unittest.main()
