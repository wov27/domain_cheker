"""
This module contains the core logic for finding, checking, and verifying domains
in parallel.

The main entry point is `run_parallel_check`, which uses a thread pool to process
multiple domains concurrently. It relies on a thread-safe `StatusManager` instance,
passed from the Flask app, to report detailed, real-time progress for each domain
and to manage the overall task state (e.g., handling stop requests).
"""
import requests
from bs4 import BeautifulSoup
import time
import whois
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# A custom exception to signal a user-requested stop
class TaskStoppedException(Exception):
    """Custom exception raised when a task is stopped by the user."""
    pass

# --- Constants ---
VT_API_V3_BASE_URL = "https://www.virustotal.com/api/v3"

# --- Main Parallel Orchestration Function ---

def run_parallel_check(url, cookies, vt_api_key, target_domain_count, max_workers, status_manager):
    """
    Finds and checks domains in parallel.

    This function orchestrates the entire checking process. It fetches a list of
    domains, then uses a ThreadPoolExecutor to run checks for each domain
    concurrently. It stops once the target number of clean domains is found or
    all domains are processed.

    Args:
        url (str): The URL from expireddomains.net to scrape.
        cookies (dict): Authentication cookies for expireddomains.net.
        vt_api_key (str): The VirusTotal API key.
        target_domain_count (int): The number of clean domains to find.
        max_workers (int): The number of parallel threads to use.
        status_manager (StatusManager): The thread-safe manager for reporting status.
    """
    status_manager.set_progress_message("Этап 1/3: Получение списка доменов...")
    
    def error_callback(msg):
        status_manager.set_progress_message(msg)

    all_domains = get_expired_domains(url, cookies, error_callback)
    if not all_domains:
        status_manager.set_progress_message("Не удалось получить домены. Проверьте URL и cookies.")
        return

    status_manager.set_total_domains(len(all_domains))
    status_manager.set_progress_message(f"Найдено {len(all_domains)} доменов. Запуск {max_workers} потоков...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(
                _check_single_domain, domain, cookies, vt_api_key, status_manager
            ): domain for domain in all_domains
        }

        for future in as_completed(future_to_domain):
            if status_manager.is_stopping() or status_manager.get_found_count() >= target_domain_count:
                for f in future_to_domain:
                    f.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                raise TaskStoppedException()

            domain = future_to_domain[future]
            try:
                is_clean = future.result()
                if is_clean:
                    status_manager.add_clean_domain(domain, f"https://www.virustotal.com/gui/domain/{domain}")
                
            except Exception as e:
                status_manager.update_domain_status(domain, f"Ошибка: {e}")
            finally:
                status_manager.remove_domain_from_progress(domain)


def _check_single_domain(domain, cookies, vt_api_key, status_manager):
    """
    Performs all checks for a single domain. Designed to be run in a thread.
    """
    if status_manager.is_stopping():
        raise TaskStoppedException()

    # Add a small delay to avoid overwhelming WHOIS servers
    time.sleep(1)
        
    # 1. WHOIS Check
    status_manager.update_domain_status(domain, "Проверка WHOIS...")
    if not is_domain_available(domain, status_manager):
        status_manager.update_domain_status(domain, "Занят (WHOIS)")
        return False

    if status_manager.is_stopping():
        raise TaskStoppedException()

    # 2. VirusTotal Check
    status_manager.update_domain_status(domain, "Проверка VirusTotal...")
    is_clean, error_message = verify_domain_with_vt(domain, vt_api_key, status_manager)
    if error_message:
        raise Exception(error_message)
    
    if not is_clean:
        status_manager.update_domain_status(domain, "Не прошел проверку VT")
        return False
        
    status_manager.update_domain_status(domain, "Чистый и доступен!")
    return True


# --- Helper Functions (modified to accept status_manager) ---

def get_expired_domains(url, cookies, update_status):
    """
    Fetches domains from expireddomains.net.
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
            first_cell = row.find('td')
            if first_cell and first_cell.a:
                domain_list.append(first_cell.a.text)
        
        return domain_list
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Ошибка сети при доступе к expireddomains.net: {e}"
        print(error_msg)
        update_status(error_msg)
        return []

def is_domain_available(domain, status_manager):
    """
    Checks if a single domain is available via WHOIS.
    This version is more robust against network errors.
    """
    try:
        w = whois.whois(domain)
        # Domain is considered available if it has no status or no creation date.
        # This logic might need adjustment depending on the TLD.
        return not w.status or not w.creation_date
    except whois.parser.PywhoisError:
        # This error often means the domain is not registered.
        return True
    except Exception as e:
        # Catch other errors (like network issues) and log them.
        # Treat as "not available" to be safe.
        status_manager.update_domain_status(domain, f"WHOIS-ошибка: {type(e).__name__}")
        print(f"WHOIS check for {domain} failed: {e}")
        return False

def verify_domain_with_vt(domain, api_key, status_manager):
    """
    Performs a full, robust VirusTotal verification for a single domain.
    This function now uses polling to wait for analysis results, which is
    more efficient than a fixed-timer wait.
    """
    def _is_report_clean(report):
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        return malicious == 0 and suspicious <= 1

    if not api_key or 'YOUR_' in api_key:
        return True, None # Default to "clean" if VT is not configured

    headers = {"x-apikey": api_key}
    domain_report_url = f"{VT_API_V3_BASE_URL}/domains/{domain}"
    
    try:
        if status_manager.is_stopping(): raise TaskStoppedException()
        status_manager.update_domain_status(domain, "VT: запрос отчета...")
        time.sleep(16) # Adhere to public API rate limits (4 req/min)
        response = requests.get(domain_report_url, headers=headers, timeout=30)

        if response.status_code == 401:
            return False, "Ошибка аутентификации VirusTotal."
        
        needs_rescan = True
        if response.status_code == 200:
            report = response.json()
            last_analysis_ts = report.get('data', {}).get('attributes', {}).get('last_analysis_date')
            if last_analysis_ts:
                last_analysis_date = datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc)
                if last_analysis_date > (datetime.now(timezone.utc) - timedelta(days=1)):
                    status_manager.update_domain_status(domain, "VT: свежий отчет, проверка...")
                    needs_rescan = False
                    return _is_report_clean(report), None
        
        if needs_rescan:
            if status_manager.is_stopping(): raise TaskStoppedException()
            status_manager.update_domain_status(domain, "VT: запуск повторного анализа...")
            rescan_url = f"{VT_API_V3_BASE_URL}/domains/{domain}/analyse"
            time.sleep(16)
            rescan_response = requests.post(rescan_url, headers=headers, timeout=30)

            if rescan_response.status_code != 200:
                 return False, f"Ошибка при запуске анализа (код: {rescan_response.status_code})."

            analysis_id = rescan_response.json().get('data', {}).get('id')
            if not analysis_id:
                return False, "Не удалось получить ID для нового анализа."
            
            analysis_status_url = f"{VT_API_V3_BASE_URL}/analyses/{analysis_id}"
            
            # Polling loop to check analysis status
            max_wait_time = 240 # 4 minutes
            poll_interval = 15  # 15 seconds
            elapsed_time = 0

            while elapsed_time < max_wait_time:
                if status_manager.is_stopping(): raise TaskStoppedException()
                
                status_manager.update_domain_status(domain, f"VT: ожидание ({int(elapsed_time)}/{max_wait_time}s)")
                time.sleep(poll_interval)
                elapsed_time += poll_interval

                status_response = requests.get(analysis_status_url, headers=headers, timeout=30)
                if status_response.status_code == 200:
                    status = status_response.json().get('data',{}).get('attributes',{}).get('status')
                    if status == 'completed':
                        status_manager.update_domain_status(domain, "VT: анализ завершен.")
                        break 
            else:
                return False, "Анализ VT занял слишком много времени."

        if status_manager.is_stopping(): raise TaskStoppedException()
        status_manager.update_domain_status(domain, "VT: получение финального отчета...")
        time.sleep(16)
        final_response = requests.get(domain_report_url, headers=headers, timeout=30)
        
        if final_response.status_code != 200:
            return False, f"Не удалось получить отчет (код: {final_response.status_code})."
            
        final_report = final_response.json()
        return _is_report_clean(final_report), None

    except TaskStoppedException:
        raise
    except requests.exceptions.RequestException as e:
        return False, f"Сетевая ошибка VT: {e}"
    except requests.exceptions.JSONDecodeError:
        return False, "Ошибка обработки ответа VT."
    except Exception as e:
        print(f"Неожиданная ошибка в verify_domain_with_vt для {domain}: {e}")
        return False, f"Неожиданная ошибка VT: {e}"
