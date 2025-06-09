"""
This module contains the core logic for finding, checking, and verifying domains.

It is designed to be called from a web application. The main entry point is the
`domain_check_generator`, which processes domains sequentially for maximum efficiency,
yielding clean, available domains one by one. It provides callbacks for status updates
and for stopping the task, making it suitable for long-running background jobs.
"""
import requests
from bs4 import BeautifulSoup
import time
import whois
from datetime import datetime, timedelta, timezone

# A custom exception to signal a user-requested stop
class TaskStoppedException(Exception):
    """Custom exception raised when a task is stopped by the user."""
    pass

# --- Constants ---
VT_API_V3_BASE_URL = "https://www.virustotal.com/api/v3"

# --- Main Orchestration Function (Generator) ---

def domain_check_generator(url, cookies, vt_api_key, target_domain_count, update_status_callback=None, check_stop_flag=None):
    """
    Finds, checks, and yields clean, available domains.

    This generator function orchestrates the entire checking process. It fetches an
    initial list of domains, then processes them one by one, performing WHOIS checks
    and full VirusTotal verification until the target number of clean domains is found.

    Args:
        url (str): The URL from expireddomains.net to scrape.
        cookies (dict): Authentication cookies for expireddomains.net.
        vt_api_key (str): The VirusTotal API key.
        target_domain_count (int): The number of clean domains to find.
        update_status_callback (function, optional): A callback function that takes a
            string message to update the UI.
        check_stop_flag (function, optional): A callback function that returns True if
            the task should be stopped.

    Yields:
        str: The next available and clean domain name.

    Raises:
        TaskStoppedException: If the `check_stop_flag` callback signals a stop.
    """
    def _update_status(message):
        if check_stop_flag and check_stop_flag():
            raise TaskStoppedException("Task stopped by user.")
        if update_status_callback:
            update_status_callback(message)

    found_count = 0
    
    _update_status("Этап 1/3: Получение списка доменов с expireddomains.net...")
    all_domains = get_expired_domains(url, cookies, _update_status)
    if not all_domains:
        _update_status("Не удалось получить домены. Проверьте URL и cookies в config.ini.")
        return

    total_domains = len(all_domains)
    _update_status(f"Найдено {total_domains} доменов. Начинаю последовательную проверку...")

    for i, domain in enumerate(all_domains):
        _update_status(f"Обработка {i+1}/{total_domains}: {domain}...")
        
        if not is_domain_available(domain, _update_status, i + 1, total_domains):
            continue
        
        is_clean, error_message = verify_domain_with_vt(domain, vt_api_key, _update_status, i + 1, total_domains)
        if error_message:
            _update_status(f"Ошибка при проверке {domain}: {error_message}")
            continue

        if is_clean:
            found_count += 1
            yield domain
        
        if found_count >= target_domain_count:
            _update_status(f"Задача выполнена. Найдено {found_count} чистых доменов.")
            break
    
    if found_count < target_domain_count:
        _update_status(f"Проверка завершена. Найдено только {found_count} из {target_domain_count} запрошенных доменов.")

# --- Helper Functions ---

def get_expired_domains(url, cookies, update_status):
    """
    Fetches domains from expireddomains.net.

    Args:
        url (str): The URL to scrape.
        cookies (dict): The authentication cookies.
        update_status (function): Callback to report errors.

    Returns:
        list: A list of domain names, or an empty list on failure.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
    }
    try:
        response = requests.get(url, headers=headers, cookies=cookies, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'lxml')
        domain_table = soup.find('table', class_='base1')
        if not domain_table:
            return []
        
        tbody = domain_table.find('tbody')
        if not tbody:
            return []

        domain_list = []
        for row in tbody.find_all('tr'):
            # The domain name is consistently in the first cell of the table row.
            first_cell = row.find('td')
            if first_cell and first_cell.a:
                domain_list.append(first_cell.a.text)
        
        return domain_list
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Ошибка сети при доступе к expireddomains.net: {e}"
        print(error_msg)
        update_status(error_msg)
        return []

def is_domain_available(domain, update_status, current, total):
    """
    Checks if a single domain is available via WHOIS.

    Args:
        domain (str): The domain name to check.
        update_status (function): Callback to update UI status.
        current (int): The current domain number in the batch.
        total (int): The total number of domains in the batch.

    Returns:
        bool: True if the domain is available, False otherwise.
    """
    update_status(f"Этап 2/3: Проверка WHOIS для {domain} ({current}/{total})")
    try:
        time.sleep(1)
        w = whois.whois(domain)
        return not w.status or not w.creation_date
    except whois.parser.PywhoisError:
        return True # Often means the domain does not exist, so it's available.
    except Exception as e:
        error_msg = f"Не удалось выполнить WHOIS-проверку для {domain}: {e}"
        print(error_msg)
        update_status(error_msg)
        return False

def verify_domain_with_vt(domain, api_key, update_status, current, total):
    """
    Performs a full, robust VirusTotal verification for a single domain.

    This function checks for a recent report, triggers a re-scan if needed,
    waits, and then checks the final report. It handles network errors,
    API errors (like bad keys), and unexpected response formats.

    Args:
        domain (str): The domain to check.
        api_key (str): The VirusTotal API key.
        update_status (function): Callback for UI status updates.
        current (int): Current domain number for progress display.
        total (int): Total domains for progress display.

    Returns:
        tuple[bool, str|None]: A tuple containing:
            - bool: True if the domain is clean, False otherwise.
            - str|None: An error message if an error occurred, otherwise None.
    """
    def _is_report_clean(report):
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        return malicious == 0 and suspicious <= 1

    if not api_key or 'YOUR_' in api_key:
        return True, None # Default to "clean" if VT is not configured

    headers = {"x-apikey": api_key}
    get_url = f"{VT_API_V3_BASE_URL}/domains/{domain}"
    
    try:
        update_status(f"Этап 3/3: Запрос отчета с VirusTotal для {domain} ({current}/{total})")
        time.sleep(16)
        response = requests.get(get_url, headers=headers, timeout=30)

        if response.status_code == 401:
            return False, "Ошибка аутентификации VirusTotal (неверный API-ключ?)."
        
        needs_rescan = True
        if response.status_code == 200:
            report = response.json()
            last_analysis_ts = report.get('data', {}).get('attributes', {}).get('last_analysis_date')
            if last_analysis_ts:
                last_analysis_date = datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc)
                if last_analysis_date > (datetime.now(timezone.utc) - timedelta(days=1)):
                    update_status(f"Отчет для {domain} свежий. Проверяю результаты...")
                    needs_rescan = False
                    return _is_report_clean(report), None
        
        if needs_rescan:
            update_status(f"Отчет для {domain} устарел или отсутствует. Запускаю повторный анализ...")
            post_url = f"{VT_API_V3_BASE_URL}/domains/{domain}/analyse"
            time.sleep(16)
            rescan_response = requests.post(post_url, headers=headers, timeout=30)
            if rescan_response.status_code == 401:
                return False, "Ошибка аутентификации VirusTotal (неверный API-ключ?)."

            update_status(f"Ожидание завершения повторного анализа {domain} (90 сек)...")
            time.sleep(90)

        update_status(f"Получение финального отчета для {domain}...")
        time.sleep(16)
        final_response = requests.get(get_url, headers=headers, timeout=30)
        
        if final_response.status_code != 200:
            return False, f"Не удалось получить финальный отчет (код: {final_response.status_code})."
            
        final_report = final_response.json()
        return _is_report_clean(final_report), None

    except requests.exceptions.RequestException as e:
        return False, f"Сетевая ошибка при работе с VirusTotal: {e}"
    except requests.exceptions.JSONDecodeError:
        return False, "Не удалось обработать ответ от VirusTotal (неверный формат JSON)."
    except Exception as e:
        print(f"An unexpected error in verify_domain_with_vt: {e}")
        return False, f"Неожиданная ошибка: {e}"