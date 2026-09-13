import os
import sys

# Добавляем текущую директорию в пути импорта Python
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Импортируем студенческий модуль аналитики
try:
    import vps_soc_analyzer as analyzer
except ImportError:
    print("[!] Не найден файл vps_soc_analyzer.py. Переименуйте шаблон или создайте его!")
    sys.exit(1)

def run_pipeline():
    print("=" * 60)
    print("ЗАПУСК КОНВЕЙЕРА (PIPELINE) МИНИ-SOC НА VPS (СТУДЕНЧЕСКИЙ ШАБЛОН)")
    print("=" * 60)

    # ==========================================
    # ПУТЬ К ПАПКЕ С ЛОГАМИ (ОБЩАЯ)
    # ==========================================
    LOG_DIR = "/home/student/logs/"

    # Конкретные файлы в этой папке
    ssh_log_path = LOG_DIR + "auth.log"
    nginx_log_path = LOG_DIR + "auth.log"   # ← ТОТ ЖЕ ФАЙЛ!
    dummy_config = "/tmp/vps_secure_config.conf"

    # ==========================================
    # ШАГ 1: Чтение логов
    # ==========================================
    print("[1] Чтение логов из папки /home/student/logs/:")

    # Читаем SSH логи
    try:
        with open(ssh_log_path, "r", encoding='utf-8') as f:
            ssh_logs = f.readlines()
        print(f"    - SSH логи: {len(ssh_logs)} строк (из {ssh_log_path})")
    except FileNotFoundError:
        print(f"    [!] Файл {ssh_log_path} не найден!")
        ssh_logs = []

    # Читаем Nginx логи
    try:
        with open(nginx_log_path, "r", encoding='utf-8') as f:
            nginx_logs = f.readlines()
        print(f"    - Nginx логи: {len(nginx_logs)} строк (из {nginx_log_path})")
    except FileNotFoundError:
        print(f"    [!] Файл {nginx_log_path} не найден!")
        nginx_logs = []

    print("-" * 60)

    # ==========================================
    # ШАГ 2: Анализ SSH логов (Брутфорс)
    # ==========================================
    print("[2] Анализ SSH логов (Brute-Force):")

    if ssh_logs:
        # ГРУППИРОВКА АТАК ПО IP
        ip_attempts = analyzer.group_by_ip(ssh_logs)

        print(f"    - Всего уникальных IP: {len(ip_attempts)}")
        for ip, count in sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"      * IP: {ip} - {count} неудачных попыток")

        # ДЕТЕКТОР БРУТФОРС-АТАК
        bf_alerts = analyzer.detect_brute_force(ip_attempts, threshold=5)

        print(f"    - ОБНАРУЖЕНО БРУТФОРС-АТАК (>= 5 попыток): {len(bf_alerts)}")
        for ip in bf_alerts:
            print(f"      [ALERT] IP {ip} превысил порог! Рекомендуется блокировка!")
    else:
        print("    [!] Нет данных для анализа SSH")
        bf_alerts = []

    print("-" * 60)

    # ==========================================
    # ШАГ 3: Анализ веб-логов (Nginx)
    # ==========================================
    print("[3] Анализ веб-логов (Nginx):")

    web_alerts_count = 0
    if nginx_logs:
        print("    - Подозрительные веб-запросы:")
        for line in nginx_logs:
            is_suspicious = analyzer.detect_suspicious_paths(line)
            if is_suspicious:
                web_alerts_count += 1
                parts = line.split('"')
                request = parts[1] if len(parts) > 1 else line.strip()
                ip = line.split()[0] if line.split() else "unknown"
                print(f"      [ALERT] {ip} запросил опасный путь: '{request[:50]}...'")
    else:
        print("    [!] Нет данных для анализа Nginx")

    print(f"    - Всего зафиксировано подозрительных веб-запросов: {web_alerts_count}")
    print("-" * 60)

    # ==========================================
    # ШАГ 4: Расчет риска
    # ==========================================
    print("[4] Оценка уровня угрозы VPS (Risk Scoring):")
    risk = analyzer.calculate_risk_score(len(bf_alerts), web_alerts_count)
    print(f"    - УРОВЕНЬ РИСКА ДЛЯ VPS: **{risk}**")
    print("-" * 60)

    # ==========================================
    # ШАГ 5: Контроль целостности файлов
    # ==========================================
    print("[5] Контроль целостности файлов на VPS:")

    with open(dummy_config, "w") as f:
        f.write("PermitRootLogin no\nPasswordAuthentication no\n")

    hash_original = analyzer.get_file_hash(dummy_config)
    print(f"    - Хеш-сумма файла: {hash_original}")

    # Симулируем несанкционированное изменение
    with open(dummy_config, "a") as f:
        f.write("PermitRootLogin yes # ХАКЕР ИЗМЕНИЛ НАСТРОЙКУ!\n")

    hash_modified = analyzer.get_file_hash(dummy_config)
    print(f"    - Хеш-сумма после изменения: {hash_modified}")

    if hash_original != hash_modified:
        print("    - [!] ВНИМАНИЕ: Целостность конфигурационного файла НАРУШЕНА!")
    else:
        print("    - [OK] Файл конфигурации не изменен.")
    print("-" * 60)

    # ==========================================
    # ШАГ 6: Проверка портов
    # ==========================================
    print("[6] Сетевая разведка (Сканер портов):")
    ports_to_scan = [22, 80, 443, 8080]
    print(f"    - Сканируем порты на localhost (127.0.0.1): {ports_to_scan}")
    for port in ports_to_scan:
        is_open = analyzer.is_port_open("127.0.0.1", port, timeout=0.5)
        status = "ОТКРЫТ" if is_open else "ЗАКРЫТ"
        print(f"      * Порт {port}: {status}")
    print("-" * 60)

    # ==========================================
    # ШАГ 7: Очистка временных файлов
    # ==========================================
    print("[7] Очистка временных файлов:")
    if os.path.exists(dummy_config):
        os.remove(dummy_config)
        print(f"    - Удалён временный файл {dummy_config}")
    else:
        print("    - Временных файлов для очистки нет")
    print("-" * 60)

    print("КОНВЕЙЕР ЗАВЕРШИЛ РАБОТУ.")
    print("=" * 60)

if __name__ == "__main__":
    run_pipeline()