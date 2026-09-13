import re
import socket
import hashlib


def extract_ip(log_line: str) -> str | None:
    """
    Кейс 1: Ищет IP-адрес в строке лога, если это похоже на попытку взлома SSH.
    """
    # Если в строке есть слова о неудачном входе — это атака
    if "Failed password" in log_line or "Invalid user" in log_line:
        # Ищем IP после слова "from" с помощью регулярного выражения
        # r'...' — сырая строка, чтобы \s и \d работали правильно
        match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
        if match:
            # match.group(1) — берём то, что в скобках (сам IP)
            return match.group(1)
        # Если атака есть, но IP не нашли — вернём None
        return None
    # Если это не атака — вернём None
    return None


def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """
    Кейс 2: Считает, сколько раз каждый IP пытался войти (неудачно).
    """
    # Создаём пустой словарь: ключ — IP, значение — сколько раз
    attacks: dict[str, int] = {}
    # Проходим по каждой строке лога
    for line in log_lines:
        # Достаём IP из строки (если он там есть)
        ip = extract_ip(line)
        if ip:
            # Если IP уже есть в словаре — увеличиваем счётчик
            # attacks.get(ip, 0) — если IP нет, вернёт 0
            attacks[ip] = attacks.get(ip, 0) + 1
    return attacks


def detect_brute_force(ip_counts: dict[str, int], threshold: int = 5) -> list[str]:
    """
    Кейс 3: Находит IP, которые превысили порог попыток (брутфорс-атака).
    """
    # Создаём пустой список для опасных IP
    DANGEROUS = []
    # Проходим по всем парам (IP, количество) в словаре
    for ip, count in ip_counts.items():
        # Если попыток больше или равно порогу — это атака
        if count >= threshold:
            DANGEROUS.append(ip)  # Добавляем IP в список
    return DANGEROUS


def detect_suspicious_paths(log_line: str) -> bool:
    """
    Кейс 4: Ищет в строке лога признаки веб-атаки (опасные пути).
    """
    # Список опасных слов, которые часто встречаются в атаках
    signatures = ['/etc/passwd', '.env', 'wp-admin', 'select+union', 'union+select', 'shell.php']
    # Приводим строку к нижнему регистру, чтобы искать без учёта регистра
    line_lower = log_line.lower()
    # Проверяем каждое опасное слово
    for sig in signatures:
        if sig in line_lower:
            return True  # Нашли — значит атака
    return False  # Ничего не нашли — безопасно


def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    """
    Кейс 5: Считает уровень риска: LOW, MEDIUM или HIGH.
    """
    # Каждая брутфорс-атака = 3 балла, каждая веб-атака = 1 балл
    score = brute_force_alerts * 3 + web_alerts * 1
    if score == 0:
        return "LOW"      # Нет атак — низкий риск
    elif score < 5:
        return "MEDIUM"   # Мало атак — средний риск
    else:
        return "HIGH"     # Много атак — высокий риск


def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Кейс 6: Проверяет, открыт ли порт на сервере (безопасный сканер).
    """
    try:
        # Создаём TCP-сокет (как «телефонная трубка» для подключения)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Ставим таймаут — если сервер не ответит за timeout секунд, считаем порт закрытым
        sock.settimeout(timeout)
        # Пытаемся подключиться к ip:port
        # connect_ex возвращает 0, если подключение успешно
        result = sock.connect_ex((ip, port))
        sock.close()  # Закрываем сокет
        # Если result == 0 — порт открыт
        return result == 0
    except Exception:
        # Если любая ошибка — считаем порт закрытым
        return False


def get_file_hash(filepath: str) -> str:
    """
    Кейс 7: Считает SHA-256 хеш файла (для проверки целостности).
    """
    try:
        # Создаём объект для вычисления хеша
        sha256 = hashlib.sha256()
        # Открываем файл в бинарном режиме ('rb')
        with open(filepath, 'rb') as f:
            # Читаем файл кусочками по 4096 байт
            while True:
                data = f.read(4096)
                if not data:  # Если кусочек пустой — файл закончился
                    break
                sha256.update(data)  # Добавляем кусочек в хеш
        # Возвращаем хеш в виде строки из 64 символов
        return sha256.hexdigest()
    except FileNotFoundError:
        # Если файл не найден — возвращаем сообщение
        return "FILE_NOT_FOUND"