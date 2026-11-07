import csv
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import tkinter as tk
import urllib.request
import zipfile
import cmdcom
import viidu_info
import miner_monitor
import runtime_protection
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "virus_signatures.db")
QUARANTINE_DIR = os.path.join(BASE_DIR, "Quarantine")
VIBROW_DIR = os.path.join(BASE_DIR, "ViBrow")
VIBROW_ZIP_URL = "https://github.com/HYXZKAKONHNK/ViBrow/archive/refs/tags/v1.1.1.zip"
EICAR_TEST_SHA256 = "13db60afb914a2ee9b3649d1947d58046d1a9e9b8e4114d80b1d5c142b4ed7fa"
EICAR_TEST_MD5 = "c637d527c86186464879dc45e7816c53"

def hash_similarity(first_hash, second_hash):
    """Схожесть хешей по совпадающим битам, от 0 до 100 процентов."""
    if not isinstance(first_hash, str) or not isinstance(second_hash, str):
        return 0.0
    if len(first_hash) != len(second_hash):
        return 0.0
    try:
        first_value = int(first_hash, 16)
        second_value = int(second_hash, 16)
    except ValueError:
        return 0.0

    bit_count = len(first_hash) * 4
    differing_bits = (first_value ^ second_value).bit_count()
    return (bit_count - differing_bits) / bit_count * 100


def calculate_sha256(file_path):
    """
    Вычисляет стандартный SHA-256 хэш файла.
    Использует поблочное чтение, чтобы не перегружать ОЗУ большими файлами.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Читаем файл блоками по 64 КБ
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest().lower()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    try:
        with open(file_path, "rb") as source:
            for byte_block in iter(lambda: source.read(65536), b""):
                md5_hash.update(byte_block)
        return md5_hash.hexdigest().lower()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def calculate_entropy(data):
    if not data:
        return 0.0
    frequencies = {value: data.count(value) for value in set(data)}
    import math
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in frequencies.values())


def heuristic_analysis(file_path):
    """Возвращает оценку подозрительности, уровень и найденные признаки без выполнения файла."""
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as source:
            data = source.read(8 * 1024 * 1024)
    except (OSError, MemoryError):
        return 0.0, "Ошибка чтения", []

    lower_data = data.lower()
    score = 0.0
    indicators = []

    is_pe = data.startswith(b"MZ") and b"PE\x00\x00" in data[:1024 * 1024]
    if is_pe:
        score += 5
        indicators.append("PE-заголовок")

    entropy = calculate_entropy(data)
    if entropy >= 7.2:
        score += 25
        indicators.append(f"Высокая энтропия {entropy:.1f}")

    suspicious_strings = {
        b"virtualallocex": "управление памятью",
        b"writeprocessmemory": "запись в другой процесс",
        b"createprocess": "создание процесса",
        b"createremotethread": "удаленный поток",
        b"regsetvalue": "изменение реестра",
        b"winhttp": "сетевой модуль",
        b"cryptencrypt": "шифрование",
        b"powershell": "запуск PowerShell",
        b"cmd.exe": "запуск командной оболочки",
    }
    found_strings = []
    for marker, label in suspicious_strings.items():
        if marker in lower_data:
            found_strings.append(label)
    if found_strings:
        score += min(40, len(found_strings) * 8)
        indicators.append("API: " + ", ".join(found_strings))

    if is_pe and file_size and file_size < 4096:
        score += 10
        indicators.append("Очень маленький PE-файл")

    suspicious_extensions = (b".bat", b".cmd", b".ps1", b".vbs")
    if any(marker in lower_data for marker in suspicious_extensions):
        score += 15
        indicators.append("Сценарии исполнения")

    if score >= 70:
        level = "Высокая подозрительность"
    elif score >= 40:
        level = "Средняя подозрительность"
    else:
        level = "Низкая подозрительность"
    return min(score, 100.0), level, indicators


def calculate_simple_fuzzy_hash(file_path, block_size=256):
    """
    Упрощенный аналог локально-чувствительного хэша на чистом Python.
    Разбивает файл на блоки, хэширует их и собирает 'отпечаток' структуры.
    """
    v = [0] * 64  # 64-битный вектор для итогового хэша
    
    try:
        with open(file_path, "rb") as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                
                # Получаем быстрый хэш от кусочка файла
                # С помощью встроенного hash() для простоты, либо через md5
                h = int(hashlib.md5(block).hexdigest(), 16)
                
                # Формируем вектор признаков (алгоритм SimHash)
                for i in range(64):
                    bit = (h >> i) & 1
                    if bit:
                        v[i] += 1
                    else:
                        v[i] -= 1
                        
        # Переводим вектор в финальное 64-битное число
        fingerprint = 0
        for i in range(64):
            if v[i] >= 0:
                fingerprint |= (1 << i)
                
        return fingerprint
    except FileNotFoundError:
        return None

def get_similarity(hash1, hash2):
    """
    Вычисляет схожесть двух нечетких хэшей (по расстоянию Хэмминга).
    Возвращает процент схожести от 0% до 100%.
    """
    # XOR показывает, какие биты различаются
    x = hash1 ^ hash2
    
    # Считаем количество единичных битов (различий)
    # метод bit_count() доступен в Python 3.10+
    diff_bits = x.bit_count() 
    
    # Переводим в проценты совпадения
    similarity = (64 - diff_bits) / 64 * 100
    return similarity

def init_database():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL UNIQUE, name TEXT NOT NULL, description TEXT, md5 TEXT)")
        try:
            connection.execute("ALTER TABLE signatures ADD COLUMN md5 TEXT")
        except sqlite3.OperationalError:
            pass
        connection.execute("CREATE INDEX IF NOT EXISTS idx_signatures_sha256 ON signatures(sha256)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_signatures_md5 ON signatures(md5)")
        connection.execute(
            "DELETE FROM signatures WHERE name = ? AND lower(trim(sha256)) = ?",
            (
                "EICAR-Test-File",
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ),
        )
        connection.execute(
            """
            INSERT INTO signatures (sha256, name, description, md5)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET md5 = excluded.md5
            """,
            (
                EICAR_TEST_SHA256.lower(),
                "EICAR-Test-File",
                "Безопасный контрольный образец антивирусной реакции",
                EICAR_TEST_MD5,
            ),
        )

        rows = connection.execute("SELECT id, sha256 FROM signatures ORDER BY id").fetchall()
        kept = set()
        for row_id, stored_hash in rows:
            normalized_hash = stored_hash.strip().lower()
            if normalized_hash in kept:
                connection.execute("DELETE FROM signatures WHERE id = ?", (row_id,))
            else:
                kept.add(normalized_hash)
        connection.execute("UPDATE signatures SET sha256 = lower(trim(sha256))")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                total_files INTEGER NOT NULL,
                threats INTEGER NOT NULL,
                notes TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                level TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS exclusions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC)")

    return DATABASE_PATH


def database_signature_count():
    with sqlite3.connect(DATABASE_PATH) as connection:
        return connection.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]



class AntivirusApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AntiVi")
        self.geometry("760x540")
        self.scanning = False
        init_database()
        self.status_var = tk.StringVar(value=f"База готова: {database_signature_count()} сигнатур")
        self.BASE_DIR = BASE_DIR
        self.DATABASE_PATH = DATABASE_PATH
        self.QUARANTINE_DIR = QUARANTINE_DIR
        self.database_signature_count = database_signature_count
        self.miner_monitor = None
        self.miner_monitor_running = False
        self.runtime_protection = None

        toolbar = ttk.Frame(self, padding=12)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Полное сканирование", command=self.start_full_scan).pack(side="left", padx=(0, 8))
        ttk.Button(toolbar, text="Сканирование определенного файла", command=self.start_file_scan).pack(side="left", padx=(0, 8))
        ttk.Button(toolbar, text="Карантин", command=self.show_quarantine).pack(side="left", padx=(0, 8))
        ttk.Button(toolbar, text="Импорт базы SHA-256", command=self.import_database).pack(side="left", padx=(0, 8))
        ttk.Button(toolbar, text="Мониторинг задач", command=self.show_task_monitor).pack(side="left", padx=(0, 8))
        ttk.Button(toolbar, text="Журнал", command=self.show_events).pack(side="left", padx=(0, 8))
        ttk.Button(toolbar, text="Исключения", command=self.show_exclusions).pack(side="left", padx=(0, 8))
        self.miner_monitor_button = ttk.Button(toolbar, text="Монитор майнеров: ВЫКЛ", command=self.toggle_miner_monitor)
        self.miner_monitor_button.pack(side="left", padx=(0, 8))
        self.protection_button = ttk.Button(toolbar, text="Постоянная защита: ВЫКЛ", command=self.toggle_runtime_protection)
        self.protection_button.pack(side="left")

        database_label = ttk.Label(self, text=f"База: {DATABASE_PATH}", anchor="w")
        database_label.pack(fill="x", padx=12, pady=(4, 0))

        columns = ("path", "status", "signature")
        self.results = ttk.Treeview(self, columns=columns, show="headings")
        self.results.heading("path", text="Файл")
        self.results.heading("status", text="Статус")
        self.results.heading("signature", text="Сигнатура")
        self.results.column("path", width=430)
        self.results.column("status", width=110)
        self.results.column("signature", width=180)
        self.results.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        progress_frame = ttk.Frame(self, padding=(12, 4, 12, 4))
        progress_frame.pack(fill="x")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.current_file_var = tk.StringVar(value="Сканирование не запущено")
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill="x")
        ttk.Label(progress_frame, textvariable=self.current_file_var, anchor="w").pack(fill="x", pady=(4, 0))

        terminal_frame = ttk.LabelFrame(self, text="Терминал AntiVix", padding=8)
        terminal_frame.pack(fill="x", padx=12, pady=(0, 8))
        self.terminal_output = tk.Text(terminal_frame, height=7, wrap="word", state="disabled")
        self.terminal_output.pack(fill="x")
        command_frame = ttk.Frame(terminal_frame)
        command_frame.pack(fill="x", pady=(6, 0))
        ttk.Label(command_frame, text="AntiVix>").pack(side="left", padx=(0, 6))
        self.terminal_command = ttk.Entry(command_frame)
        self.terminal_command.pack(side="left", fill="x", expand=True)
        self.terminal_command.bind("<Return>", lambda _event: self.execute_terminal_command())
        ttk.Button(command_frame, text="Выполнить", command=self.execute_terminal_command).pack(side="left", padx=(6, 0))
        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(12, 8)).pack(fill="x")
        self.terminal_append("Команды: help | clear | dwnl vibrow")

    def log_event(self, level, source, message):
        with sqlite3.connect(DATABASE_PATH) as connection:
            connection.execute(
                "INSERT INTO events (created_at, level, source, message) VALUES (?, ?, ?, ?)",
                (datetime.now().isoformat(timespec="seconds"), level, source, message),
            )

    def toggle_miner_monitor(self):
        if self.miner_monitor_running:
            if self.miner_monitor:
                self.miner_monitor.stop()
            self.miner_monitor_running = False
            self.miner_monitor_button.configure(text="Монитор майнеров: ВЫКЛ")
            self.log_event("INFO", "miner-monitor", "Постоянный монитор майнеров остановлен")
        else:
            self.miner_monitor = miner_monitor.MinerActivityMonitor(
                event_callback=self.handle_miner_suspicion,
                interval=5,
            )
            self.miner_monitor_running = self.miner_monitor.start()
            if self.miner_monitor_running:
                self.miner_monitor_button.configure(text="Монитор майнеров: ВКЛ")
                self.log_event("WARNING", "miner-monitor", "Постоянный монитор майнеров запущен")

    def toggle_runtime_protection(self):
        if self.runtime_protection and self.runtime_protection.running:
            self.runtime_protection.stop()
            if self.miner_monitor_running:
                self.toggle_miner_monitor()
            self.protection_button.configure(text="Постоянная защита: ВЫКЛ")
            self.log_event("INFO", "runtime-protection", "Постоянная защита остановлена")
            return

        self.runtime_protection = runtime_protection.RuntimeFileProtection(
            scan_callback=self.scan_new_file,
        )
        started = self.runtime_protection.start()
        if started:
            self.protection_button.configure(text="Постоянная защита: ВКЛ")
            if not self.miner_monitor_running:
                self.toggle_miner_monitor()
            self.log_event("WARNING", "runtime-protection", "Постоянная защита запущена")

    def scan_new_file(self, file_path):
        if self.is_excluded(file_path):
            return
        result = self.scan_path(file_path)
        if result:
            status, signature = result
            self.log_event("WARNING" if status == "Карантин" else "INFO", "runtime-protection",
                           f"{status}: {file_path} {signature}")

    def is_protected_system_path(self, file_path):
        if not file_path:
            return True
        normalized = os.path.normcase(os.path.abspath(file_path))
        windows_root = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
        program_files = os.path.normcase(os.environ.get("ProgramFiles", r"C:\Program Files"))
        return normalized.startswith(windows_root + os.sep) or normalized.startswith(program_files + os.sep)

    def handle_miner_suspicion(self, finding):
        indicators = "; ".join(finding["indicators"])
        message = (
            f"PID {finding['pid']}, {finding['name']}, score={finding['score']:.0f}%: {indicators}"
        )
        self.log_event("WARNING", "miner-monitor", message)
        self.after(0, self.status_var.set, "Возможная майнер-активность: " + message)

        if finding["score"] >= 90 and not self.is_protected_system_path(finding["path"]):
            try:
                subprocess.run(
                    ["taskkill.exe", "/PID", str(finding["pid"]), "/T", "/F"],
                    timeout=15,
                    check=True,
                )
                self.log_event("CRITICAL", "runtime-protection",
                               "Подозрительный майнер-процесс завершен: " + message)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                self.log_event("ERROR", "runtime-protection",
                               f"Не удалось завершить PID {finding['pid']}: {error}")

    def is_excluded(self, file_path):
        normalized_path = os.path.normcase(os.path.abspath(file_path))
        extension = os.path.normcase(os.path.splitext(file_path)[1].lower())
        with sqlite3.connect(DATABASE_PATH) as connection:
            for kind, value in connection.execute("SELECT kind, value FROM exclusions").fetchall():
                normalized_value = os.path.normcase(os.path.abspath(value)) if kind == "file" else value.lower()
                if kind == "file" and normalized_path == normalized_value:
                    return True
                if kind == "folder" and normalized_path.startswith(os.path.normcase(os.path.abspath(value)) + os.sep):
                    return True
                if kind == "extension" and extension == normalized_value:
                    return True
        return False

    def lookup_signature(self, sha256_hash, md5_hash=None):
        if not isinstance(sha256_hash, str) or len(sha256_hash.strip()) != 64:
            return None
        normalized_hash = sha256_hash.strip().lower()
        normalized_md5 = md5_hash.strip().lower() if isinstance(md5_hash, str) else None

        try:
            int(normalized_hash, 16)
        except ValueError:
            return None
        if normalized_md5:
            try:
                if len(normalized_md5) != 32:
                    normalized_md5 = None
                else:
                    int(normalized_md5, 16)
            except ValueError:
                normalized_md5 = None

        with sqlite3.connect(DATABASE_PATH) as connection:
            exact_sha = connection.execute(
                "SELECT name FROM signatures WHERE lower(trim(sha256)) = ?",
                (normalized_hash,),
            ).fetchone()
            if exact_sha:
                return exact_sha[0], 100.0, "SHA-256"

            for stored_hash, name in connection.execute(
                "SELECT sha256, name FROM signatures WHERE sha256 IS NOT NULL"
            ).fetchall():
                similarity = hash_similarity(normalized_hash, stored_hash.strip().lower())
                if similarity >= 95.0:
                    return name, similarity, "SHA-256"

            if normalized_md5 is None:
                return None

            for stored_hash, name in connection.execute(
                "SELECT md5, name FROM signatures WHERE md5 IS NOT NULL AND trim(md5) <> ''"
            ).fetchall():
                similarity = hash_similarity(normalized_md5, stored_hash.strip().lower())
                if similarity >= 85.0:
                    return name, similarity, "MD5"
            return None

    def quarantine_file(self, file_path):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.basename(file_path)
        destination = os.path.join(QUARANTINE_DIR, f"{timestamp}_{base_name}")
        counter = 1
        while os.path.exists(destination):
            destination = os.path.join(QUARANTINE_DIR, f"{timestamp}_{counter}_{base_name}")
            counter += 1
        try:
            shutil.move(file_path, destination)
        except OSError as error:
            return f"Ошибка карантина: {error}", None
        record = {"original_path": file_path, "quarantine_path": destination,
                  "quarantined_at": datetime.now().isoformat(timespec="seconds")}
        with open(destination + ".json", "w", encoding="utf-8") as manifest:
            json.dump(record, manifest, ensure_ascii=False, indent=2)
        return "Карантин", destination

    def scan_path(self, file_path):
        if not os.path.isfile(file_path) or os.path.islink(file_path):
            return None
        if self.is_excluded(file_path):
            return "Исключено", ""
        digest = calculate_sha256(file_path)
        if digest is None:
            return "Ошибка чтения", ""
        md5_digest = calculate_md5(file_path)
        match = self.lookup_signature(digest, md5_digest)
        if match is not None:
            name, similarity, method = match
            status, _ = self.quarantine_file(file_path)
            return status, f"{name} ({method} {similarity:.1f}%)"

        heuristic_score, heuristic_level, indicators = heuristic_analysis(file_path)
        if heuristic_score >= 70.0:
            status, _ = self.quarantine_file(file_path)
            details = "; ".join(indicators) if indicators else heuristic_level
            return status, f"Эвристика {heuristic_score:.1f}%: {details}"
        if indicators:
            return "Подозрительно", f"Эвристика {heuristic_score:.1f}%: {heuristic_level}"
        return "Чисто", ""

    def run_scan(self, paths, scan_type="manual"):
        started_at = datetime.now()
        self.after(0, self.results.delete, *self.results.get_children())
        self.after(0, self.progress_var.set, 0.0)
        threats = 0
        total = len(paths)
        for index, path in enumerate(paths, start=1):
            percent = (index / total * 100) if total else 100.0
            self.after(0, self.current_file_var.set, f"{percent:.1f}%  Проверяется: {path}")
            self.after(0, self.progress_var.set, percent)
            result = self.scan_path(path)
            if result:
                status, signature = result
                values = (path, status, signature)
                self.after(0, self.results.insert, "", "end", values=values)
                threats += status == "Карантин"
            self.after(0, self.status_var.set,
                      f"Проверено {index} из {total} ({percent:.1f}%)")
        self.after(0, self.current_file_var.set, "Сканирование завершено")
        self.after(0, self.progress_var.set, 100.0)
        finished_at = datetime.now()
        self.after(0, self.status_var.set,
                  f"Сканирование завершено. Угроз помещено в карантин: {threats}")
        with sqlite3.connect(DATABASE_PATH) as connection:
            connection.execute(
                "INSERT INTO scan_history (started_at, finished_at, scan_type, total_files, threats, notes) VALUES (?, ?, ?, ?, ?, ?)",
                (started_at.isoformat(timespec="seconds"), finished_at.isoformat(timespec="seconds"), scan_type, total, threats,
                 "Сканирование завершено"),
            )
        self.log_event("INFO", "scan", f"Проверено {total} файлов, обнаружено угроз: {threats}")
        self.after(0, setattr, self, "scanning", False)

    def available_drives(self):
        drives = []
        if os.name == "nt":
            import string
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
        else:
            drives.append(os.path.sep)
        return drives

    def start_folder_scan(self, root):
        if self.scanning:
            messagebox.showinfo("Сканирование", "Сканирование уже выполняется")
            return

        paths = []
        try:
            for directory, directories, names in os.walk(root, onerror=lambda _error: None):
                directories[:] = [
                    name for name in directories
                    if not os.path.islink(os.path.join(directory, name))
                ]
                for name in names:
                    paths.append(os.path.join(directory, name))
        except (OSError, PermissionError) as error:
            messagebox.showerror("Сканирование", str(error))
            return

        self.scanning = True
        self.progress_var.set(0.0)
        self.current_file_var.set(f"Найдено файлов: {len(paths)}")
        self.status_var.set(f"Найдено файлов: {len(paths)}")
        if paths:
            threading.Thread(target=self.run_scan, args=(paths,), daemon=True).start()
        else:
            self.scanning = False
            self.status_var.set("В папке нет доступных файлов")

    def start_full_scan(self):
        if self.scanning:
            messagebox.showinfo("Сканирование", "Сканирование уже выполняется")
            return

        drives = self.available_drives()
        if not drives:
            messagebox.showerror("Сканирование", "Диски для сканирования не найдены")
            return
        if not messagebox.askyesno(
            "Полное сканирование",
            "Сканировать все доступные диски:\n" + "\n".join(drives),
        ):
            return

        self.scanning = True
        self.progress_var.set(0.0)
        self.current_file_var.set("Сбор списка файлов на всех дисках...")
        self.status_var.set("Сбор списка файлов на всех дисках...")

        def collect_files():
            paths = []
            for drive in drives:
                try:
                    for directory, directories, names in os.walk(drive, onerror=lambda _error: None):
                        directories[:] = [
                            name for name in directories
                            if not os.path.islink(os.path.join(directory, name))
                            and name.lower() not in {"node_modules", "$recycle.bin"}
                        ]
                        for name in names:
                            paths.append(os.path.join(directory, name))
                            if len(paths) % 100 == 0:
                                self.after(0, self.current_file_var.set,
                                          f"Собрано файлов: {len(paths)} — последний: {os.path.join(directory, name)}")
                except (OSError, PermissionError):
                    continue
            self.after(0, self.status_var.set, f"Найдено файлов: {len(paths)}")
            if paths:
                self.run_scan(paths)
            else:
                self.after(0, self.status_var.set, "Доступных файлов для сканирования не найдено")
                self.after(0, setattr, self, "scanning", False)

        threading.Thread(target=collect_files, daemon=True).start()

    def start_file_scan(self):
        if self.scanning:
            messagebox.showinfo("Сканирование", "Сканирование уже выполняется")
            return
        path = filedialog.askopenfilename(title="Выберите файл для сканирования")
        if not path:
            return
        if not os.path.isfile(path):
            messagebox.showerror("Сканирование", "Выбранный путь не является файлом")
            return
        self.scanning = True
        self.results.delete(*self.results.get_children())
        self.status_var.set(f"Сканируется файл: {path}")
        threading.Thread(target=self.run_scan, args=([path],), daemon=True).start()

    def terminal_append(self, text):
        self.after(0, self._terminal_append_now, text)

    def _terminal_append_now(self, text):
        self.terminal_output.configure(state="normal")
        self.terminal_output.insert("end", str(text) + "\n")
        self.terminal_output.see("end")
        self.terminal_output.configure(state="disabled")

    def _terminal_clear_now(self):
        self.terminal_output.configure(state="normal")
        self.terminal_output.delete("1.0", "end")
        self.terminal_output.configure(state="disabled")

    def execute_terminal_command(self):
        command = self.terminal_command.get().strip()
        if not command:
            return
        self.terminal_command.delete(0, "end")
        self.terminal_append(f"AntiVix> {command}")
        result = cmdcom.execute(self, command)
        if result:
            for line in str(result).splitlines():
                self.terminal_append(line)

    def download_vibrow(self):
        self.terminal_append("Загрузка ViBrow 1.1.1...")
        try:
            os.makedirs(VIBROW_DIR, exist_ok=True)
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as archive_file:
                archive_path = archive_file.name
            request = urllib.request.Request(VIBROW_ZIP_URL, headers={"User-Agent": "AntiVix"})
            with urllib.request.urlopen(request, timeout=60) as response, open(archive_path, "wb") as output:
                shutil.copyfileobj(response, output)

            destination = os.path.abspath(VIBROW_DIR)
            with zipfile.ZipFile(archive_path, "r") as archive:
                for member in archive.infolist():
                    member_path = os.path.abspath(os.path.join(destination, member.filename))
                    if os.path.commonpath((destination, member_path)) != destination:
                        raise ValueError(f"Недопустимый путь в ZIP: {member.filename}")
                archive.extractall(destination)

            os.remove(archive_path)
            self.terminal_append(f"ViBrow распакован в: {VIBROW_DIR}")
            self.status_var.set("ViBrow 1.1.1 скачан и распакован")
        except (OSError, ValueError, zipfile.BadZipFile, urllib.error.URLError) as error:
            self.terminal_append(f"Ошибка загрузки ViBrow: {error}")
            self.status_var.set("Не удалось скачать ViBrow")

    def import_database(self):
        path = filedialog.askopenfilename(
            title="Выберите CSV-базу SHA-256",
            filetypes=[("CSV базы", "*.csv"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        imported = 0
        try:
            with open(path, "r", encoding="utf-8-sig", newline="") as source:
                reader = csv.DictReader(source)
                required = {"sha256", "name"}
                if reader.fieldnames is None or not required.issubset(field.strip().lower() for field in reader.fieldnames):
                    raise ValueError("CSV должен содержать заголовки sha256,name")

                normalized_fields = {field.strip().lower(): field for field in reader.fieldnames}
                with sqlite3.connect(DATABASE_PATH) as connection:
                    for row in reader:
                        sha256 = row[normalized_fields["sha256"]].strip().lower()
                        name = row[normalized_fields["name"]].strip()
                        description_field = normalized_fields.get("description")
                        description = row[description_field].strip() if description_field else ""
                        md5_field = normalized_fields.get("md5")
                        md5 = row[md5_field].strip().lower() if md5_field else ""
                        if len(sha256) != 64:
                            continue
                        try:
                            int(sha256, 16)
                            if md5 and len(md5) == 32:
                                int(md5, 16)
                            elif md5:
                                md5 = ""
                        except ValueError:
                            continue
                        if not name:
                            continue
                        cursor = connection.execute(
                            """
                            INSERT INTO signatures (sha256, name, description, md5)
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(sha256) DO UPDATE SET
                                name = excluded.name,
                                description = excluded.description,
                                md5 = CASE WHEN excluded.md5 <> '' THEN excluded.md5 ELSE signatures.md5 END
                            """,
                            (sha256, name, description, md5),
                        )
                        imported += cursor.rowcount
            self.status_var.set(f"Импортировано записей: {imported}. Всего в базе: {database_signature_count()}")
            messagebox.showinfo("Импорт базы", f"Импорт завершен. Всего записей: {database_signature_count()}")
        except (OSError, csv.Error, UnicodeError, ValueError) as error:
            messagebox.showerror("Импорт базы", f"Не удалось импортировать CSV: {error}")

    def show_events(self):
        window = tk.Toplevel(self)
        window.title("Журнал и история сканирования")
        window.geometry("900x520")
        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        events_tab = ttk.Frame(notebook)
        history_tab = ttk.Frame(notebook)
        notebook.add(events_tab, text="Журнал событий")
        notebook.add(history_tab, text="История сканирования")

        events_tree = ttk.Treeview(events_tab, columns=("time", "level", "source", "message"), show="headings")
        for column, title, width in (
            ("time", "Время", 150), ("level", "Уровень", 90),
            ("source", "Источник", 150), ("message", "Сообщение", 450),
        ):
            events_tree.heading(column, text=title)
            events_tree.column(column, width=width)
        events_tree.pack(fill="both", expand=True)

        history_tree = ttk.Treeview(history_tab, columns=("start", "finish", "type", "files", "threats", "notes"), show="headings")
        for column, title, width in (
            ("start", "Начало", 150), ("finish", "Конец", 150),
            ("type", "Тип", 100), ("files", "Файлов", 80),
            ("threats", "Угроз", 80), ("notes", "Примечание", 250),
        ):
            history_tree.heading(column, text=title)
            history_tree.column(column, width=width)
        history_tree.pack(fill="both", expand=True)

        with sqlite3.connect(DATABASE_PATH) as connection:
            for event in connection.execute(
                "SELECT created_at, level, source, message FROM events ORDER BY id DESC LIMIT 500"
            ).fetchall():
                events_tree.insert("", "end", values=event)
            for scan in connection.execute(
                "SELECT started_at, finished_at, scan_type, total_files, threats, notes FROM scan_history ORDER BY id DESC LIMIT 500"
            ).fetchall():
                history_tree.insert("", "end", values=scan)

    def show_exclusions(self):
        window = tk.Toplevel(self)
        window.title("Исключения")
        window.geometry("720x420")

        controls = ttk.Frame(window, padding=8)
        controls.pack(fill="x")
        ttk.Button(controls, text="Добавить папку", command=lambda: add_folder()).pack(side="left", padx=(0, 6))
        ttk.Button(controls, text="Добавить файл", command=lambda: add_file()).pack(side="left", padx=(0, 6))
        ttk.Button(controls, text="Добавить расширение", command=lambda: add_extension()).pack(side="left")

        tree = ttk.Treeview(window, columns=("kind", "value"), show="headings")
        tree.heading("kind", text="Тип")
        tree.heading("value", text="Путь или расширение")
        tree.column("kind", width=120)
        tree.column("value", width=560)
        tree.pack(fill="both", expand=True, padx=8, pady=8)

        def refresh():
            for item in tree.get_children():
                tree.delete(item)
            with sqlite3.connect(DATABASE_PATH) as connection:
                for row in connection.execute("SELECT kind, value FROM exclusions ORDER BY kind, value"):
                    tree.insert("", "end", values=row)

        def add_exclusion(kind, value):
            if not value:
                return
            value = value.strip().lower() if kind == "extension" else value.strip()
            if kind == "extension" and not value.startswith("."):
                value = "." + value
            with sqlite3.connect(DATABASE_PATH) as connection:
                connection.execute("INSERT OR IGNORE INTO exclusions (kind, value) VALUES (?, ?)", (kind, value))
            refresh()

        def add_folder():
            add_exclusion("folder", filedialog.askdirectory(title="Исключить папку"))

        def add_file():
            add_exclusion("file", filedialog.askopenfilename(title="Исключить файл"))

        def add_extension():
            dialog = tk.Toplevel(window)
            dialog.title("Расширение")
            entry = ttk.Entry(dialog)
            entry.pack(fill="x", padx=12, pady=12)
            def save_extension():
                add_exclusion("extension", entry.get())
                dialog.destroy()
            ttk.Button(dialog, text="Добавить", command=save_extension).pack(pady=(0, 12))

        def remove_selected():
            selection = tree.selection()
            if not selection:
                return
            kind, value = tree.item(selection[0], "values")
            with sqlite3.connect(DATABASE_PATH) as connection:
                connection.execute("DELETE FROM exclusions WHERE kind = ? AND value = ?", (kind, value))
            refresh()

        ttk.Button(window, text="Удалить выбранное исключение", command=remove_selected).pack(pady=(0, 8))
        refresh()

    def read_processes(self):
        if os.name != "nt":
            return []
        command = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "$OutputEncoding = [System.Text.Encoding]::UTF8; "
            "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,WorkingSetSize,Status,ExecutablePath "
            "| ConvertTo-Csv -NoTypeInformation"
        )
        try:
            output = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                timeout=15,
                check=False,
            )
            if output.returncode != 0:
                return []
            stdout = output.stdout.decode("utf-8-sig", errors="replace")
            rows = list(csv.DictReader(stdout.splitlines()))
            processes = []
            for row in rows:
                memory_bytes = int(row.get("WorkingSetSize") or 0)
                processes.append({
                    "pid": row.get("ProcessId", ""),
                    "name": row.get("Name", ""),
                    "memory": memory_bytes,
                    "status": row.get("Status") or "Running",
                    "path": row.get("ExecutablePath") or "",
                })
            return sorted(processes, key=lambda process: (process["name"].lower(), int(process["pid"] or 0)))
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return []

    def show_task_monitor(self):
        window = tk.Toplevel(self)
        window.title("Мониторинг задач")
        window.geometry("900x500")

        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)
        processes_tab = ttk.Frame(notebook, padding=0)
        diagnostics_tab = ttk.Frame(notebook, padding=8)
        notebook.add(processes_tab, text="Процессы")
        notebook.add(diagnostics_tab, text="Диагностическая утилита")

        controls = ttk.Frame(processes_tab, padding=8)
        controls.pack(fill="x")
        ttk.Label(controls, text="Поиск:").pack(side="left")
        search_var = tk.StringVar()
        search_entry = ttk.Entry(controls, textvariable=search_var)
        search_entry.pack(side="left", fill="x", expand=True, padx=(6, 8))
        ttk.Button(controls, text="Обновить", command=lambda: refresh()).pack(side="left", padx=(0, 8))
        ttk.Button(controls, text="Завершить процесс", command=lambda: terminate_selected()).pack(side="left")

        columns = ("pid", "name", "memory", "status", "path")
        task_tree = ttk.Treeview(processes_tab, columns=columns, show="headings")
        task_tree.heading("pid", text="PID")
        task_tree.heading("name", text="Процесс")
        task_tree.heading("memory", text="Память")
        task_tree.heading("status", text="Статус")
        task_tree.heading("path", text="Путь")
        task_tree.column("pid", width=70, anchor="center")
        task_tree.column("name", width=180)
        task_tree.column("memory", width=110, anchor="e")
        task_tree.column("status", width=100)
        task_tree.column("path", width=430)
        task_tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        info_var = tk.StringVar(value="Обновление задач...")
        ttk.Label(processes_tab, textvariable=info_var, anchor="w", padding=(8, 0, 8, 8)).pack(fill="x")

        diagnostic_toolbar = ttk.Frame(diagnostics_tab)
        diagnostic_toolbar.pack(fill="x")
        diagnostic_status = tk.StringVar(value="Диагностика готова к обновлению")
        ttk.Button(diagnostic_toolbar, text="Обновить диагностику", command=lambda: refresh_diagnostics()).pack(side="left")
        ttk.Label(diagnostic_toolbar, textvariable=diagnostic_status).pack(side="left", padx=8)

        diagnostic_output = tk.Text(diagnostics_tab, wrap="word", font=("Consolas", 10))
        diagnostic_output.pack(fill="both", expand=True, pady=(8, 0))

        def refresh_diagnostics():
            diagnostic_status.set("Сбор системной информации...")

            def collect():
                info = viidu_info.collect_system_info()
                report = "VIIDU — Диагностическая утилита\n\n"
                report += "\n".join(f"{name}: {value}" for name, value in info.items())
                window.after(0, show_diagnostic_report, report)

            threading.Thread(target=collect, daemon=True).start()

        def show_diagnostic_report(report):
            diagnostic_output.configure(state="normal")
            diagnostic_output.delete("1.0", "end")
            diagnostic_output.insert("1.0", report)
            diagnostic_output.configure(state="disabled")
            diagnostic_status.set("Диагностика обновлена")

        process_refresh_job = None

        def refresh():
            nonlocal process_refresh_job
            try:
                if not window.winfo_exists():
                    return
            except tk.TclError:
                return
            processes = self.read_processes()
            query = search_var.get().strip().lower()
            for item in task_tree.get_children():
                task_tree.delete(item)
            visible = 0
            for process in processes:
                if query and query not in process["name"].lower() and query not in process["pid"]:
                    continue
                memory_mb = process["memory"] / 1024 / 1024
                task_tree.insert("", "end", values=(
                    process["pid"], process["name"], f"{memory_mb:.1f} МБ",
                    process["status"], process["path"],
                ))
                visible += 1
            info_var.set(f"Процессов: {visible} из {len(processes)}")
            try:
                if window.winfo_exists():
                    if process_refresh_job is not None:
                        window.after_cancel(process_refresh_job)
                    process_refresh_job = window.after(2000, refresh)
            except tk.TclError:
                pass

        def terminate_selected():
            selection = task_tree.selection()
            if not selection:
                messagebox.showwarning("Мониторинг задач", "Выберите процесс")
                return
            pid = task_tree.item(selection[0], "values")[0]
            name = task_tree.item(selection[0], "values")[1]
            if not messagebox.askyesno("Завершение процесса", f"Завершить {name} (PID {pid})?"):
                return
            try:
                subprocess.run(["taskkill.exe", "/PID", str(pid), "/T", "/F"], check=True, timeout=15)
                refresh()
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                messagebox.showerror("Мониторинг задач", f"Не удалось завершить процесс: {error}")

        search_entry.bind("<KeyRelease>", lambda _event: refresh())
        refresh()
        refresh_diagnostics()

    def show_quarantine(self):
        window = tk.Toplevel(self)
        window.title("Карантин")
        window.geometry("620x320")
        listbox = tk.Listbox(window)
        listbox.pack(fill="both", expand=True, padx=12, pady=12)
        found = False
        if os.path.isdir(QUARANTINE_DIR):
            for name in sorted(os.listdir(QUARANTINE_DIR)):
                if not name.endswith(".json"):
                    listbox.insert("end", name)
                    found = True
        if not found:
            listbox.insert("end", "Карантин пуст")


if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()

# тут раньше был код где была переменная furry_virus1 и furry_virus2 и ахаха фури вирусы
# но пришлось удалить, тк это заглушки были
# мой друг скидывеет мне фури бойкисеров осуждаю его
# хэш который напечатала моя кошка: 15rvdcn259543nkmcl12ngf890vg2h1uio2y1890ojbdhnvujijkm394i1488ekj
# это вирус который орет мяу и делает лапки на экране и я далбаеб
# и я это выдумал
# но это все равно очень опасный вирус и он меняет раскладку клавиатуры на фури раскладку и я не могу писать на нормальной клавиатуре
# и я скачал клавиатуру фури бойкисер а671488 это хорошая клавиатура
# она тап тап и приятно и там гейкапы меняющиеся
# а что я этот умный или да ли нет
# хантавирус