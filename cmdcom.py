"""Команды встроенного терминала AntiVix."""

import os
import threading

VIBROW_ALIASES = {"vibrow", "webbrowser", "browser", "antivi-browser"}


def execute(app, command):
    """Выполнить встроенную команду AntiVix."""
    parts = command.strip().split()
    if not parts:
        return ""

    name = parts[0].lower()

    if name == "help":
        return "\n".join((
            "Доступные команды:",
            "help, clear, dwnl <имя>, scan file <путь>, scan folder <путь>",
            "status, drives, database, signatures, quarantine, files, browser, about",
            "exit, restart, update-db, clean-quarantine confirm",
        ))

    if name == "clear":
        app.after(0, app._terminal_clear_now)
        return ""

    if name == "sysapp exit":
        app.after(0, app.destroy)
        return "Приложение закрывается"

    if name == "status":
        return f"Сканирование: {'активно' if app.scanning else 'остановлено'}"

    if name == "drives":
        drives = app.available_drives()
        return "Диски: " + ", ".join(drives if drives else ["не найдены"])

    if name == "database":
        return f"База: {app.DATABASE_PATH}"

    if name == "signatures":
        return f"Сигнатур в базе: {app.database_signature_count()}"

    if name == "quarantine":
        app.after(0, app.show_quarantine)
        return "Окно карантина открыто"

    if name == "files":
        if os.path.isdir(app.BASE_DIR):
            names = sorted(name for name in os.listdir(app.BASE_DIR) if not name.startswith("."))[:20]
            return "Файлы: " + (", ".join(names) if names else "пусто")
        return "Папка приложения не найдена"

    if name == "browser":
        return "Используйте: dwnl vibrow"

    if name == "about":
        return "AntiVix — локальный сканер SHA-256, MD5 и эвристического анализа"

    if name == "restart":
        app.after(0, app.destroy)
        return "Перезапустите приложение вручную"

    if name == "update-db":
        app.after(0, app.import_database)
        return "Выберите CSV-файл базы"

    if name == "clean-quarantine":
        if len(parts) != 2 or parts[1].lower() != "confirm":
            return "Подтверждение: clean-quarantine confirm"
        removed = 0
        if os.path.isdir(app.QUARANTINE_DIR):
            for entry in os.listdir(app.QUARANTINE_DIR):
                path = os.path.join(app.QUARANTINE_DIR, entry)
                if os.path.isfile(path) or os.path.islink(path):
                    os.remove(path)
                    removed += 1
        return f"Удалено из карантина: {removed}"

    if name == "scan" and len(parts) >= 2:
        target_type = parts[1].lower()
        target = " ".join(parts[2:]).strip()
        if target_type == "file":
            if target and os.path.isfile(target):
                app.scanning = True
                app.results.delete(*app.results.get_children())
                threading.Thread(target=app.run_scan, args=([target],), daemon=True).start()
                return f"Сканируется файл: {target}"
            return "Файл не найден: " + (target or "путь не указан")
        if target_type == "folder":
            if target and os.path.isdir(target):
                app.start_folder_scan(target)
                return f"Сканируется папка: {target}"
            return "Папка не найдена: " + (target or "путь не указан")
        return "Использование: scan file <путь> или scan folder <путь>"

    if name == "dwnl":
        if len(parts) != 2 or parts[1].lower() not in VIBROW_ALIASES:
            return "Использование: dwnl vibrow"
        threading.Thread(target=app.download_vibrow, daemon=True).start()
        return ""

    return f"Неизвестная команда: {name}. Введите help"
