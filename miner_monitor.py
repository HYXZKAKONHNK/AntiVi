"""Легковесный постоянный монитор подозрительной майнер-активности."""

import os
import re
import threading
import time

try:
    import psutil
except ImportError:
    psutil = None

MINER_NAMES = (
    "xmrig", "minerd", "ethminer", "nbminer", "phoenixminer",
    "t-rex", "trexminer", "gminer", "lolminer", "cpuminer",
    "nicehash", "kryptex",
)
SYSTEM_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "spoolsv.exe", "runtimebroker.exe", "searchhost.exe",
    "taskhostw.exe", "securityhealthservice.exe", "antivi.exe",
}

MINER_MARKERS = (
    "stratum+tcp://", "stratum+ssl://", "miningpoolhub",
    "2miners.com", "ethermine.org", "poolin.com",
    "nanopool.org", "supportxmr.com", "moneroocean.stream",
    "--algo", "--coin", "wallet", "rig-id",
)


def is_miner_process(process):
    try:
        name = (process.name() or "").lower()
        command_line = " ".join(process.cmdline()).lower()
    except (psutil.Error, OSError, AttributeError):
        return False, []

    indicators = []
    if any(marker in name for marker in MINER_NAMES):
        indicators.append("имя майнер-программы")

    for marker in MINER_MARKERS:
        if marker in command_line:
            indicators.append(f"аргумент майнинг-пула: {marker}")
            break

    return bool(indicators), indicators


class MinerActivityMonitor:
    def __init__(self, event_callback=None, interval=5):
        self.event_callback = event_callback
        self.interval = interval
        self.running = False
        self.thread = None
        self._reported_processes = {}

    def start(self):
        if self.running or psutil is None:
            return False
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        self.running = False

    def _emit(self, process_id, name, path, score, indicators):
        if self.event_callback:
            self.event_callback({
                "pid": process_id,
                "name": name,
                "path": path,
                "score": score,
                "indicators": indicators,
            })

    def _loop(self):
        while self.running:
            self._check_processes()
            time.sleep(self.interval)

    def _check_processes(self):
        if psutil is None:
            return
        system_root = os.path.normcase(os.environ.get("SystemRoot", "C:\\Windows"))
        program_files = os.path.normcase(os.environ.get("ProgramFiles", "C:\\Program Files"))
        for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                process_id = process.info["pid"]
                if process_id <= 4:
                    continue
                name = (process.info.get("name") or "Неизвестно").lower()
                path = process.info.get("exe") or ""
                normalized_path = os.path.normcase(os.path.abspath(path)) if path else ""
                if name in SYSTEM_NAMES:
                    continue
                if normalized_path.startswith(system_root + os.sep) or normalized_path.startswith(program_files + os.sep):
                    continue
                suspicious, indicators = is_miner_process(process)
                score = 0

                if suspicious:
                    score = 85 + min(15, len(indicators) * 5)

                try:
                    cpu_percent = process.cpu_percent(interval=None)
                    if suspicious and cpu_percent >= 70:
                        indicators.append(f"высокая загрузка CPU: {cpu_percent:.1f}%")
                        score = max(score, 70)
                except (psutil.Error, OSError):
                    cpu_percent = 0

                if score >= 70:
                    current_time = time.monotonic()
                    last_reported = self._reported_processes.get(process_id, 0)
                    if current_time - last_reported >= 60:
                        self._reported_processes[process_id] = current_time
                        self._emit(process_id, name, path, min(score, 100), indicators)
            except (psutil.Error, OSError, KeyError):
                continue
