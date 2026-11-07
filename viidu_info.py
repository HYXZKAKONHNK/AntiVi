"""Сбор системной диагностики для окна мониторинга AntiVi."""

import platform
import shutil
import subprocess
import os

try:
    import psutil
except ImportError:
    psutil = None


def _run_powershell(script):
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            timeout=12,
            check=False,
        )
        return result.stdout.decode("utf-8-sig", errors="replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return "Неизвестно"


def _gib(value):
    return round(value / 1024 ** 3, 1) if value else 0.0


def collect_system_info():
    memory = psutil.virtual_memory() if psutil else None
    swap = psutil.swap_memory() if psutil else None
    battery = psutil.sensors_battery() if psutil else None
    system_drive = os.environ.get("SystemDrive", os.path.abspath(os.sep))
    disk = shutil.disk_usage(system_drive)

    cpu_name = _run_powershell("(Get-CimInstance Win32_Processor | Select-Object -First 1).Name")
    gpu_name = _run_powershell("(Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name) -join ', '" )
    motherboard = _run_powershell("(Get-CimInstance Win32_BaseBoard | Select-Object -First 1).Product")
    bios = _run_powershell("(Get-CimInstance Win32_BIOS | Select-Object -First 1).SMBIOSBIOSVersion")
    ip_address = _run_powershell("Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*'} | Select-Object -First 1 -ExpandProperty IPAddress")
    mac_address = _run_powershell("Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty MacAddress")

    return {
        "Система": platform.platform(),
        "Архитектура": platform.machine(),
        "Процессор": cpu_name,
        "Физические ядра": psutil.cpu_count(logical=False) if psutil else "Неизвестно",
        "Логические потоки": psutil.cpu_count(logical=True) if psutil else "Неизвестно",
        "Видеокарта": gpu_name,
        "Материнская плата": motherboard,
        "BIOS": bios,
        "IP-адрес": ip_address,
        "MAC-адрес": mac_address,
        "ОЗУ всего": f"{_gib(memory.total)} ГБ" if memory else "Неизвестно",
        "ОЗУ доступно": f"{_gib(memory.available)} ГБ" if memory else "Неизвестно",
        "ОЗУ занято": f"{memory.percent}%" if memory else "Неизвестно",
        "Файл подкачки всего": f"{_gib(swap.total)} ГБ" if swap else "Неизвестно",
        "Диск всего": f"{_gib(disk.total)} ГБ",
        "Диск свободно": f"{_gib(disk.free)} ГБ",
        "Батарея": f"{battery.percent}%" if battery else "Не подключена",
        "Питание": "Сеть" if battery and battery.power_plugged else ("Батарея" if battery else "Неизвестно"),
    }
