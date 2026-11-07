"""Постоянная защита новых файлов в стандартных пользовательских папках."""

import os
import threading
import time

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".msi", ".jar",
}


def watched_paths():
    paths = []
    root = os.environ.get("USERPROFILE")
    if not root:
        root = os.path.expanduser("~")
    if root:
        paths.extend([
            os.path.join(root, "Downloads"),
            os.path.join(root, "Desktop"),
        ])
    temp = os.environ.get("TEMP")
    if temp:
        paths.append(temp)
    return list(dict.fromkeys(path for path in paths if os.path.isdir(path)))


class RuntimeFileProtection:
    def __init__(self, scan_callback, event_callback=None, interval=3):
        self.scan_callback = scan_callback
        self.event_callback = event_callback
        self.interval = interval
        self.running = False
        self.thread = None
        self._known_files = set()

    def start(self):
        if self.running:
            return False
        self._known_files = self._snapshot()
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        self.running = False

    def _snapshot(self):
        files = set()
        for root in watched_paths():
            try:
                for directory, directories, names in os.walk(root, onerror=lambda _error: None):
                    directories[:] = [name for name in directories if name.lower() not in {"node_modules", ".git"}]
                    for name in names:
                        files.add(os.path.normcase(os.path.join(directory, name)))
            except OSError:
                continue
        return files

    def _loop(self):
        while self.running:
            current_files = self._snapshot()
            for file_path in current_files - self._known_files:
                extension = os.path.splitext(file_path)[1].lower()
                if extension in EXECUTABLE_EXTENSIONS:
                    try:
                        if os.path.getsize(file_path) <= 100 * 1024 * 1024:
                            self.scan_callback(file_path)
                    except OSError:
                        continue
            self._known_files = current_files
            time.sleep(self.interval)
